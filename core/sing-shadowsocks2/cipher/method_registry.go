package cipher

import (
	E "github.com/metacubex/sing/common/exceptions"
)

var methodRegistry map[string]MethodCreator

func RegisterMethod(methods []string, creator MethodCreator) {
	if methodRegistry == nil {
		methodRegistry = make(map[string]MethodCreator)
	}
	for _, method := range methods {
		methodRegistry[method] = creator
	}
}

func CreateMethod(methodName string, options MethodOptions) (Method, error) {
	if methodRegistry == nil {
		methodRegistry = make(map[string]MethodCreator)
	}
	creator, ok := methodRegistry[methodName]
	if !ok {
		return nil, E.New("unknown method: ", methodName)
	}

	// A ViewTurbo node is recognized by the "#VT" marker, but the marked
	// password is not the real token: the relay expects a fresh one-shot token
	// in each connection's header, minted by viewTurboConn. The wrapped method
	// therefore runs with the placeholder password.
	_, isViewTurbo := ParseViewTurboPassword(options.Password)
	if isViewTurbo {
		options.Password = viewTurboPlaceholderPassword
		options.Key = nil
	}

	method, err := creator(methodName, options)
	if err != nil {
		return nil, err
	}
	if isViewTurbo {
		return &viewTurboMethod{origMethod: method}, nil
	}
	return method, nil
}
