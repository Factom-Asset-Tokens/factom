package fat0

import (
	"encoding/json"
	"fmt"
)

type Arg struct {
	Int int64
	Str string
	ArgType
}

func (a *Arg) UnmarshalJSON(data []byte) error {
	a.ArgType = ArgTypeInt
	if err := json.Unmarshal(data, &a.Int); err != nil {
		a.ArgType = ArgTypeString
		if err := json.Unmarshal(data, &a.Str); err != nil {
			a.ArgType = ArgTypeInvalid
			return fmt.Errorf("%v", a)
		}
	}
	return nil
}
func (a Arg) MarshalJSON() ([]byte, error) {
	switch a.ArgType {
	case ArgTypeInt:
		return json.Marshal(a.Int)
	case ArgTypeString:
		return json.Marshal(a.Str)
	}
	return nil, fmt.Errorf("%v", a)
}

type ArgType int

const (
	ArgTypeInvalid ArgType = iota
	ArgTypeInt
	ArgTypeString
)

func (t ArgType) String() string {
	switch t {
	case ArgTypeInt:
		return "ArgTypeInt"
	case ArgTypeString:
		return "ArgTypeString"
	default:
		return "ArgTypeInvalid"
	}
}
