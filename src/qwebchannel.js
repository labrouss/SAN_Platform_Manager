// qwebchannel.js — Qt 5.15 WebChannel client
// Copyright (C) 2016 The Qt Company Ltd. LGPL-3.0-only / GPL-3.0-only
"use strict";
var QWebChannelMessageTypes = {
    signal: 1,
    propertyUpdate: 2,
    init: 3,
    idle: 4,
    debug: 5,
    invokeMethod: 6,
    connectToSignal: 7,
    disconnectFromSignal: 8,
    setProperty: 9,
    response: 10,
};
var QWebChannel = function(transport, initCallback) {
    if (typeof transport !== "object" || typeof transport.send !== "function") {
        console.error("The QWebChannel requires a transport object with a send function and onmessage callback property." +
            " Given is: transport: " + typeof(transport));
        return;
    }
    var channel = this;
    this.transport = transport;
    this.send = function(data) {
        if (typeof data !== "string") {
            data = JSON.stringify(data);
        }
        channel.transport.send(data);
    };
    this.onmessage = function(message) {
        var data = message.data;
        if (typeof data === "string") {
            data = JSON.parse(data);
        }
        switch (data.type) {
            case QWebChannelMessageTypes.signal:
                channel.handleSignal(data);
                break;
            case QWebChannelMessageTypes.response:
                channel.handleResponse(data);
                break;
            case QWebChannelMessageTypes.propertyUpdate:
                channel.handlePropertyUpdate(data);
                break;
            default:
                console.error("invalid message received:", message.data);
                break;
        }
    };
    transport.onmessage = this.onmessage;
    this.execCallbacks = {};
    this.execId = 0;
    this.exec = function(data, callback) {
        if (!callback) {
            channel.send(data);
            return;
        }
        if (channel.execId === Number.MAX_VALUE) {
            channel.execId = Number.MIN_VALUE;
        }
        if (data.hasOwnProperty("id")) {
            console.error("Cannot exec message with property id: " + JSON.stringify(data));
            return;
        }
        data.id = channel.execId++;
        channel.execCallbacks[data.id] = callback;
        channel.send(data);
    };
    this.objects = {};
    this.handleSignal = function(message) {
        var object = channel.objects[message.object];
        if (object) {
            object.signalEmitted(message.signal, message.args);
        } else {
            console.warn("Unhandled signal: " + message.object + "::" + message.signal);
        }
    };
    this.handleResponse = function(message) {
        if (!message.hasOwnProperty("id")) {
            console.error("Invalid response message received: ", JSON.stringify(message));
            return;
        }
        channel.execCallbacks[message.id](message.data);
        delete channel.execCallbacks[message.id];
    };
    this.handlePropertyUpdate = function(message) {
        for (var i in message.data) {
            var data = message.data[i];
            var object = channel.objects[data.object];
            if (object) {
                object.propertyUpdate(data.signals, data.properties);
            } else {
                console.warn("Unhandled property update: " + data.object + "::" + data.signal);
            }
        }
        channel.exec({type: QWebChannelMessageTypes.idle});
    };
    this.debug = function(message) {
        channel.send({type: QWebChannelMessageTypes.debug, data: message});
    };
    channel.exec({type: QWebChannelMessageTypes.init}, function(data) {
        for (var objectName in data) {
            var object = new QObject(objectName, data[objectName], channel);
        }
        channel.exec({type: QWebChannelMessageTypes.idle});
        if (initCallback) {
            initCallback(channel);
        }
        channel.initialized = true;
    });
};
function QObject(name, data, webChannel) {
    this.__id__ = name;
    webChannel.objects[name] = this;
    var object = this;
    this.unwrapQObject = function(response) {
        if (response instanceof Array) {
            return response.map(function(qobj) {
                return object.unwrapQObject(qobj);
            });
        }
        if (!(response instanceof Object)) {
            return response;
        }
        if (!response["__QObject*__"] || response.id === undefined) {
            var jsobject = {};
            for (var propName in response) {
                jsobject[propName] = object.unwrapQObject(response[propName]);
            }
            return jsobject;
        }
        var objectId = response.id;
        if (webChannel.objects[objectId]) {
            return webChannel.objects[objectId];
        }
        if (!response.data) {
            console.error("Cannot unwrap unknown QObject " + objectId + " without data.");
            return;
        }
        var qObject = new QObject(objectId, response.data, webChannel);
        qObject.destroyed.connect(function() {
            if (webChannel.objects[objectId] === qObject) {
                delete webChannel.objects[objectId];
                var destroyedSignal = qObject["destroyed"];
                if (destroyedSignal) {
                    destroyedSignal.disconnect();
                }
            }
        });
        return qObject;
    };
    this.unwrapQObjects = function(args) {
        return args.map(function(arg) {
            return object.unwrapQObject(arg);
        });
    };
    this.propertyUpdate = function(signals, propertyMap) {
        for (var propertyIndex in propertyMap) {
            var propertyValue = propertyMap[propertyIndex];
            var propertyName = object.__propertyCache__[propertyIndex];
            object[propertyName] = object.unwrapQObject(propertyValue);
        }
        for (var signalIndex in signals) {
            var signalData = signals[signalIndex];
            var signalName = object.__signalCache__[signalData[0]];
            var args = object.unwrapQObjects(signalData[1]);
            object[signalName].emit.apply(object, args);
        }
    };
    this.signalEmitted = function(signalName, signalArgs) {
        var object = this;
        if (object.__signals__[signalName]) {
            object.__signals__[signalName].emit.apply(object, object.unwrapQObjects(signalArgs));
        } else {
            object[signalName].emit.apply(object, object.unwrapQObjects(signalArgs));
        }
    };
    function SignalObject(signalName, signalIndex, webChannel) {
        this.connect = function(callback) {
            if (typeof callback !== "function") {
                console.error("Bad callback given to connect to signal " + signalName);
                return;
            }
            object.__objectSignals__[signalIndex] = object.__objectSignals__[signalIndex] || [];
            object.__objectSignals__[signalIndex].push(callback);
            if (signalIndex !== 1) {
                webChannel.exec({
                    type: QWebChannelMessageTypes.connectToSignal,
                    object: object.__id__,
                    signal: signalIndex
                });
            }
        };
        this.disconnect = function(callback) {
            if (typeof callback !== "function") {
                console.error("Bad callback given to disconnect from signal " + signalName);
                return;
            }
            var connections = object.__objectSignals__[signalIndex];
            if (!connections) { return; }
            var idx = connections.indexOf(callback);
            if (idx < 0) {
                console.error("Cannot find connection of signal " + signalName + " to " + callback.name);
                return;
            }
            connections.splice(idx, 1);
            if (connections.length === 0 && signalIndex !== 1) {
                webChannel.exec({
                    type: QWebChannelMessageTypes.disconnectFromSignal,
                    object: object.__id__,
                    signal: signalIndex
                });
            }
        };
        this.emit = function() {
            var args = Array.prototype.slice.call(arguments);
            var connections = object.__objectSignals__[signalIndex];
            if (connections) {
                connections.forEach(function(callback) {
                    callback.apply(callback, args);
                });
            }
        };
    }
    this.__objectSignals__ = {};
    this.__propertyCache__ = {};
    this.__signalCache__ = {};
    this.__signals__ = {};
    for (var methodName in data.methods) {
        var methodInfo = data.methods[methodName];
        object[methodName] = (function(methodName, methodIdx) {
            return function() {
                var args = [];
                var callback;
                for (var i = 0; i < arguments.length; ++i) {
                    var argument = arguments[i];
                    if (typeof argument === "function") {
                        callback = argument;
                    } else if (argument instanceof QObject && webChannel.objects[argument.__id__] !== undefined) {
                        args.push({id: argument.__id__});
                    } else {
                        args.push(argument);
                    }
                }
                webChannel.exec({
                    type: QWebChannelMessageTypes.invokeMethod,
                    object: object.__id__,
                    method: methodIdx,
                    args: args
                }, function(response) {
                    if (response !== undefined) {
                        var result = object.unwrapQObject(response);
                        if (callback) {
                            callback(result);
                        }
                    } else if (callback) {
                        callback();
                    }
                });
            };
        })(methodName, methodInfo[0]);
    }
    for (var signalName in data.signals) {
        var signalIdx = data.signals[signalName];
        var signalObject = new SignalObject(signalName, signalIdx, webChannel);
        object[signalName] = signalObject;
        object.__signalCache__[signalIdx] = signalName;
        object.__signals__[signalName] = signalObject;
    }
    for (var propertyIndex in data.properties) {
        var propertyData = data.properties[propertyIndex];
        var propertyName = propertyData[0];
        var propertyValue = propertyData[1];
        object.__propertyCache__[propertyIndex] = propertyName;
        (function(propertyIndex, propertyName, propertyValue) {
            object[propertyName] = object.unwrapQObject(propertyValue);
        })(propertyIndex, propertyName, propertyValue);
    }
    object["destroyed"] = new SignalObject("destroyed", 1, webChannel);
}
if (typeof module === 'object') {
    module.exports = { QWebChannel: QWebChannel };
}
