package java

import (
	"encoding/binary"
	"errors"
	"io"
)

var ByteOrder = binary.BigEndian

type ClassAccessFlags uint16

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.1
type ClassFile struct {
	Magic             uint32
	MinorVersion      uint16
	MajorVersion      uint16
	ConstantPoolCount uint16
	ConstantPool      []Constant
	AccessFlags       ClassAccessFlags
	ThisClass         ConstantPoolIndex
	SuperClass        ConstantPoolIndex
	InterfacesCount   uint16
	Interfaces        []ConstantPoolIndex
	FieldsCount       uint16
	Fields            []*FieldInfo
	MethodsCount      uint16
	Methods           []*MethodInfo
	AttributesCount   uint16
	Attributes        []Attribute
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.1-200-E.1
const (
	PublicClass     ClassAccessFlags = 0x0001
	FinalClass                       = 0x0010
	SuperClass                       = 0x0020
	InterfaceClass                   = 0x0200
	AbstractClass                    = 0x0400
	SyntheticClass                   = 0x1000
	AnnotationClass                  = 0x2000
	EnumClass                        = 0x4000
)

type ConstantPoolIndex uint16
type ConstantPool []Constant

type ConstantType uint8

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4
type CpInfo struct {
	Tag ConstantType
	// Info []uint8
}

type Constant interface {
	Read(io.Reader) error
	Write(io.Writer) error

	GetTag() ConstantType

	Class() *ClassInfo
	Field() *FieldrefInfo
	Method() *MethodrefInfo
	InterfaceMethod() *InterfaceMethodrefInfo
	String() *StringInfo
	Integer() *IntegerInfo
	Float() *FloatInfo
	Long() *LongInfo
	Double() *DoubleInfo
	NameAndType() *NameAndTypeInfo
	Utf8() *Utf8Info
	MethodHandle() *MethodHandleInfo
	MethodType() *MethodTypeInfo
	InvokeDynamic() *InvokeDynamicInfo
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4-140
const (
	ClassConstant                  ConstantType = 7
	FieldRefConstant                            = 9
	MethodrefInfoConstant                       = 10
	InterfaceMethodrefInfoConstant              = 11
	StringConstant                              = 8
	IntegerConstant                             = 3
	FloatConstant                               = 4
	LongConstant                                = 5
	DoubleConstant                              = 6
	NameAndTypeConstant                         = 12
	Utf8Constant                                = 1
	MethodHandleConstant                        = 15
	MethodTypeConstant                          = 16
	InvokeDynamicConstant                       = 18
)

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.1
type ClassInfo struct {
	CpInfo
	NameIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.2
type FieldrefInfo struct {
	CpInfo
	ClassIndex       ConstantPoolIndex
	NameAndTypeIndex ConstantPoolIndex
}

type MethodrefInfo struct {
	CpInfo
	ClassIndex       ConstantPoolIndex
	NameAndTypeIndex ConstantPoolIndex
}

type InterfaceMethodrefInfo struct {
	CpInfo
	ClassIndex       ConstantPoolIndex
	NameAndTypeIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.3
type StringInfo struct {
	CpInfo
	StringIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.4
type IntegerInfo struct {
	CpInfo
	Value int32
}

type FloatInfo struct {
	CpInfo
	Value float32
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.5
type LongInfo struct {
	CpInfo
	Value int64
}

type DoubleInfo struct {
	CpInfo
	Value float64
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.6
type NameAndTypeInfo struct {
	CpInfo
	NameIndex       ConstantPoolIndex
	DescriptorIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.7
type Utf8Info struct {
	CpInfo
	Length uint16
	Value  string
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.8
type MethodHandleInfo struct {
	CpInfo
	ReferenceKind  uint8
	ReferenceIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.9
type MethodTypeInfo struct {
	CpInfo
	DescriptorIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.10
type InvokeDynamicInfo struct {
	CpInfo
	BootstrapMethodAttrIndex ConstantPoolIndex
	NameAndTypeIndex         ConstantPoolIndex
}

type FieldAccessFlags uint16

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.5
type FieldInfo struct {
	AccessFlags     FieldAccessFlags
	NameIndex       ConstantPoolIndex
	DescriptorIndex ConstantPoolIndex
	AttributesCount uint16
	Attributes      []Attribute
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.5-200-A.1
const (
	PublicField    FieldAccessFlags = 0x0001
	PrivateField                    = 0x0002
	ProtectedField                  = 0x0004
	StaticField                     = 0x0008
	FinalField                      = 0x0010
	VolatileField                   = 0x0040
	TransientField                  = 0x0080
	SyntheticField                  = 0x1000
	EnumField                       = 0x4000
)

type MethodAccessFlags uint16

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.6
type MethodInfo struct {
	AccessFlags     MethodAccessFlags
	NameIndex       ConstantPoolIndex
	DescriptorIndex ConstantPoolIndex
	AttributesCount uint16
	Attributes      []Attribute
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.6-200-A.1
const (
	PublicMethod       MethodAccessFlags = 0x0001
	PrivateMethod                        = 0x0002
	ProtectedMethod                      = 0x0004
	StaticMethod                         = 0x0008
	FinalMethod                          = 0x0010
	SynchronizedMethod                   = 0x0020
	BridgeMethod                         = 0x0040
	VarargsMethod                        = 0x0080
	NativeMethod                         = 0x0100
	AbstractMethod                       = 0x0400
	StrictMethod                         = 0x0800
	SyntheticMethod                      = 0x1000
)

type AttributeType uint8

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7
type AttributeInfo struct {
	AttributeNameIndex ConstantPoolIndex
	AttributeLength    uint32
	// Info []uint8
}

type Attribute interface {
	Read(io.Reader, ConstantPool) error
	Write(io.Writer) error

	GetTag() AttributeType

	ConstantValueAttribute() *ConstantValueAttribute
	CodeAttribute() *CodeAttribute
	StackMapTableAttribute() *StackMapTableAttribute
	ExceptionsAttribute() *ExceptionsAttribute
	InnerClassesAttribute() *InnerClassesAttribute
	EnclosingMethodAttribute() *EnclosingMethodAttribute
	SyntheticAttribute() *SyntheticAttribute
	SignatureAttribute() *SignatureAttribute
	SourceFileAttribute() *SourceFileAttribute
	SourceDebugExtensionAttribute() *SourceDebugExtensionAttribute
	LineNumberTableAttribute() *LineNumberTableAttribute
	LocalVariableTableAttribute() *LocalVariableTableAttribute
	LocalVariableTypeTableAttribute() *LocalVariableTypeTableAttribute
	DeprecatedAttribute() *DeprecatedAttribute
	RuntimeVisibleAnnotationsAttribute() *RuntimeVisibleAnnotationsAttribute
	RuntimeInvisibleAnnotationsAttribute() *RuntimeInvisibleAnnotationsAttribute
	RuntimeVisibleParameterAnnotationsAttribute() *RuntimeVisibleParameterAnnotationsAttribute
	RuntimeInvisibleParameterAnnotationsAttribute() *RuntimeInvisibleParameterAnnotationsAttribute
	AnnotationDefaultAttribute() *AnnotationDefaultAttribute
	BootstrapMethodsAttribute() *BootstrapMethodsAttribute
	UnknownAttribute() *UnknownAttribute
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7-300
const (
	ConstantValueTag AttributeType = iota
	CodeTag
	StackMapTableTag
	ExceptionsTag
	InnerClassesTag
	EnclosingMethodTag
	SyntheticTag
	SignatureTag
	SourceFileTag
	SourceDebugExtensionTag
	LineNumberTableTag
	LocalVariableTableTag
	LocalVariableTypeTableTag
	DeprecatedTag
	RuntimeVisibleAnnotationsTag
	RuntimeInvisibleAnnotationsTag
	RuntimeVisibleParameterAnnotationsTag
	RuntimeInvisibleParameterAnnotationsTag
	AnnotationDefaultTag
	BootstrapMethodsTag
	UnknownTag
)

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.2
type ConstantValueAttribute struct {
	AttributeInfo
	ConstantValueIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.3
type CodeAttribute struct {
	AttributeInfo
	MaxStack            uint16
	MaxLocals           uint16
	CodeLength          uint32
	Code                []uint8
	NumberOfExceptions  uint16
	ExceptionIndexTable []ExceptionIndexTableValue
	AttributesCount     uint16
	Attributes          []Attribute
}

type ExceptionIndexTableValue struct {
	StartPC   uint16
	EndPC     uint16
	HandlerPC uint16
	CatchType ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.4
type StackMapTableAttribute struct {
	AttributeInfo
	// NumberOfEntries uint16
	// Entries []StackMapFrame
	Data []uint8
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.5
type ExceptionsAttribute struct {
	AttributeInfo
	NumberOfExceptions  uint16
	ExceptionIndexTable []ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.6
type InnerClassesAttribute struct {
	AttributeInfo
	NumberOfClasses uint16
	Classes         []InnerClass
}

type InnerClass struct {
	InnerClassInfoIndex   ConstantPoolIndex
	OuterClassInfoIndex   ConstantPoolIndex
	InnerNameIndex        ConstantPoolIndex
	InnerClassAccessFlags InnerClassAccessFlags
}

type InnerClassAccessFlags uint16

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.6-300-D.2-5
const (
	PublicInnerClass     InnerClassAccessFlags = 0x0001
	PrivateInnerClass                          = 0x0002
	ProtectedInnerClass                        = 0x0004
	StaticInnerClass                           = 0x0008
	FinalInnerClass                            = 0x0010
	InterfaceInnerClass                        = 0x0200
	AbstractInnerClass                         = 0x0400
	SyntheticInnerClass                        = 0x1000
	AnnotationInnerClass                       = 0x2000
	EnumInnerClass                             = 0x4000
)

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.7
type EnclosingMethodAttribute struct {
	AttributeInfo
	ClassIndex  ConstantPoolIndex
	MethodIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.8
type SyntheticAttribute struct {
	AttributeInfo
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.9
type SignatureAttribute struct {
	AttributeInfo
	SignatureIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.10
type SourceFileAttribute struct {
	AttributeInfo
	SourceFileIndex ConstantPoolIndex
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.11
type SourceDebugExtensionAttribute struct {
	AttributeInfo
	DebugExtensionLength uint32
	DebugExtension       string
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.12
type LineNumberTableAttribute struct {
	AttributeInfo
	LineNumberTableLength uint16
	LineNumberTable       []LineNumber
}

type LineNumber struct {
	StartPC    uint16
	LineNumber uint16
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.13
type LocalVariableTableAttribute struct {
	AttributeInfo
	LocalVariableTableLength uint16
	LocalVariableTable       []LocalVariable
}

type LocalVariable struct {
	StartPC         uint16
	Length          uint16
	NameIndex       ConstantPoolIndex
	DescriptorIndex ConstantPoolIndex
	Index           uint16
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.14
type LocalVariableTypeTableAttribute struct {
	AttributeInfo
	LocalVariableTypeTableLength uint16
	LocalVariableTypeTable       []LocalVariableType
}

type LocalVariableType struct {
	StartPC        uint16
	Length         uint16
	NameIndex      ConstantPoolIndex
	SignatureIndex ConstantPoolIndex
	Index          uint16
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.15
type DeprecatedAttribute struct {
	AttributeInfo
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.16
type RuntimeVisibleAnnotationsAttribute struct {
	AttributeInfo
	// NumAnnotations uint16
	// Annotations []Annotation
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.17
type RuntimeInvisibleAnnotationsAttribute struct {
	AttributeInfo
	// NumAnnotations uint16
	// Annotations []Annotation
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.18
type RuntimeVisibleParameterAnnotationsAttribute struct {
	AttributeInfo
	// NumParameters uint8
	// ParameterAnnotations []ParameterAnnotation
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.19
type RuntimeInvisibleParameterAnnotationsAttribute struct {
	AttributeInfo
	// NumParameters uint8
	// ParameterAnnotations []ParameterAnnotation
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.20
type AnnotationDefaultAttribute struct {
	AttributeInfo
	// DefaultValue ElementValue
}

// http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.21
type BootstrapMethodsAttribute struct {
	AttributeInfo
	NumBootstrapMethods uint16
	BootstrapMethods    []BootstrapMethod
}

type BootstrapMethod struct {
	BootstrapMethodRef    ConstantPoolIndex
	NumBootstrapArguments uint16
	BootstrapArguments    []ConstantPoolIndex
}

type UnknownAttribute struct {
	AttributeInfo
	Data []uint8
}

func ReadClassFile(r io.Reader) (*ClassFile, error) {
	c := &ClassFile{}

	// Read magic.
	if err := binary.Read(r, ByteOrder, &c.Magic); err != nil {
		return nil, err
	}

	// Read version.
	if err := binary.Read(r, ByteOrder, &c.MinorVersion); err != nil {
		return nil, err
	}

	if err := binary.Read(r, ByteOrder, &c.MajorVersion); err != nil {
		return nil, err
	}

	// Read constant pool.
	if err := binary.Read(r, ByteOrder, &c.ConstantPoolCount); err != nil {
		return nil, err
	}

	c.ConstantPool = make(ConstantPool, c.ConstantPoolCount)

	for i := uint16(1); i < c.ConstantPoolCount; i++ {
		constBase := CpInfo{}

		if err := binary.Read(r, ByteOrder, &constBase.Tag); err != nil {
			return nil, err
		}

		var constant Constant
		switch constBase.GetTag() {
		case ClassConstant:
			constant = &ClassInfo{CpInfo: constBase}
		case FieldRefConstant:
			constant = &FieldrefInfo{CpInfo: constBase}
		case MethodrefInfoConstant:
			constant = &MethodrefInfo{CpInfo: constBase}
		case InterfaceMethodrefInfoConstant:
			constant = &InterfaceMethodrefInfo{CpInfo: constBase}
		case StringConstant:
			constant = &StringInfo{CpInfo: constBase}
		case IntegerConstant:
			constant = &IntegerInfo{CpInfo: constBase}
		case FloatConstant:
			constant = &FloatInfo{CpInfo: constBase}
		case LongConstant:
			constant = &LongInfo{CpInfo: constBase}
		case DoubleConstant:
			constant = &DoubleInfo{CpInfo: constBase}
		case NameAndTypeConstant:
			constant = &NameAndTypeInfo{CpInfo: constBase}
		case Utf8Constant:
			constant = &Utf8Info{CpInfo: constBase}
		case MethodHandleConstant:
			constant = &MethodHandleInfo{CpInfo: constBase}
		case MethodTypeConstant:
			constant = &MethodTypeInfo{CpInfo: constBase}
		case InvokeDynamicConstant:
			constant = &InvokeDynamicInfo{CpInfo: constBase}
		default:
			return nil, errors.New("unknown constant pool tag")
		}

		if err := constant.Read(r); err != nil {
			return nil, err
		}

		c.ConstantPool[i-1] = constant

		if constant.GetTag() == LongConstant ||
			constant.GetTag() == DoubleConstant {
			i++
		}
	}

	// Read access flags.
	if err := binary.Read(r, ByteOrder, &c.AccessFlags); err != nil {
		return nil, err
	}

	// Read this class.
	if err := binary.Read(r, ByteOrder, &c.ThisClass); err != nil {
		return nil, err
	}

	// Read super class.
	if err := binary.Read(r, ByteOrder, &c.SuperClass); err != nil {
		return nil, err
	}

	// Read interfaces.
	if err := binary.Read(r, ByteOrder, &c.InterfacesCount); err != nil {
		return nil, err
	}

	c.Interfaces = make([]ConstantPoolIndex, c.InterfacesCount)

	if err := binary.Read(r, ByteOrder, c.Interfaces); err != nil {
		return nil, err
	}

	// Read fields.
	if err := binary.Read(r, ByteOrder, &c.FieldsCount); err != nil {
		return nil, err
	}

	c.Fields = make([]*FieldInfo, 0, c.FieldsCount)

	for i := uint16(0); i < c.FieldsCount; i++ {
		field := &FieldInfo{}

		if err := binary.Read(r, ByteOrder, &field.AccessFlags); err != nil {
			return nil, err
		}

		if err := binary.Read(r, ByteOrder, &field.NameIndex); err != nil {
			return nil, err
		}

		if err := binary.Read(r, ByteOrder, &field.DescriptorIndex); err != nil {
			return nil, err
		}

		var err error
		field.AttributesCount, field.Attributes, err = readAttributes(r, c.ConstantPool)
		if err != nil {
			return nil, err
		}

		c.Fields = append(c.Fields, field)
	}

	// Read methods.
	if err := binary.Read(r, ByteOrder, &c.MethodsCount); err != nil {
		return nil, err
	}

	c.Methods = make([]*MethodInfo, 0, c.MethodsCount)

	for i := uint16(0); i < c.MethodsCount; i++ {
		method := &MethodInfo{}

		if err := binary.Read(r, ByteOrder, &method.AccessFlags); err != nil {
			return nil, err
		}

		if err := binary.Read(r, ByteOrder, &method.NameIndex); err != nil {
			return nil, err
		}

		if err := binary.Read(r, ByteOrder, &method.DescriptorIndex); err != nil {
			return nil, err
		}

		var err error
		method.AttributesCount, method.Attributes, err = readAttributes(r, c.ConstantPool)
		if err != nil {
			return nil, err
		}

		c.Methods = append(c.Methods, method)
	}

	// Read attributes.
	var err error
	c.AttributesCount, c.Attributes, err = readAttributes(r, c.ConstantPool)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *ClassFile) Write(w io.Writer) error {
	// Write magic.
	if err := binary.Write(w, ByteOrder, c.Magic); err != nil {
		return err
	}

	// Write version.
	if err := binary.Write(w, ByteOrder, c.MinorVersion); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, c.MajorVersion); err != nil {
		return err
	}

	// Write constant pool.
	if err := binary.Write(w, ByteOrder, c.ConstantPoolCount); err != nil {
		return err
	}

	for i := uint16(0); i < c.ConstantPoolCount-1; i++ {
		constant := c.ConstantPool[i]

		if constant == nil {
			continue
		}

		if err := constant.Write(w); err != nil {
			return err
		}
	}

	// Write access flags.
	if err := binary.Write(w, ByteOrder, c.AccessFlags); err != nil {
		return err
	}

	// Write this class.
	if err := binary.Write(w, ByteOrder, c.ThisClass); err != nil {
		return err
	}

	// Write super class.
	if err := binary.Write(w, ByteOrder, c.SuperClass); err != nil {
		return err
	}

	// Write interfaces.
	if err := binary.Write(w, ByteOrder, c.InterfacesCount); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, c.Interfaces); err != nil {
		return err
	}

	// Write fields.
	if err := binary.Write(w, ByteOrder, c.FieldsCount); err != nil {
		return err
	}

	for _, field := range c.Fields {
		if err := binary.Write(w, ByteOrder, field.AccessFlags); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, field.NameIndex); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, field.DescriptorIndex); err != nil {
			return err
		}

		if err := writeAttributes(w, field.AttributesCount, field.Attributes); err != nil {
			return err
		}
	}

	// Write methods.
	if err := binary.Write(w, ByteOrder, c.MethodsCount); err != nil {
		return err
	}

	for _, method := range c.Methods {
		if err := binary.Write(w, ByteOrder, method.AccessFlags); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, method.NameIndex); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, method.DescriptorIndex); err != nil {
			return err
		}

		if err := writeAttributes(w, method.AttributesCount, method.Attributes); err != nil {
			return err
		}
	}

	// Write attributes.
	if err := writeAttributes(w, c.AttributesCount, c.Attributes); err != nil {
		return err
	}

	return nil
}

func (b CpInfo) GetTag() ConstantType {
	return b.Tag
}

func (b CpInfo) Class() *ClassInfo {
	return nil
}

func (b CpInfo) Field() *FieldrefInfo {
	return nil
}

func (b CpInfo) Method() *MethodrefInfo {
	return nil
}

func (b CpInfo) InterfaceMethod() *InterfaceMethodrefInfo {
	return nil
}

func (b CpInfo) String() *StringInfo {
	return nil
}

func (b CpInfo) Integer() *IntegerInfo {
	return nil
}

func (b CpInfo) Float() *FloatInfo {
	return nil
}

func (b CpInfo) Long() *LongInfo {
	return nil
}

func (b CpInfo) Double() *DoubleInfo {
	return nil
}

func (b CpInfo) NameAndType() *NameAndTypeInfo {
	return nil
}

func (b CpInfo) Utf8() *Utf8Info {
	return nil
}

func (b CpInfo) MethodHandle() *MethodHandleInfo {
	return nil
}

func (b CpInfo) MethodType() *MethodTypeInfo {
	return nil
}

func (b CpInfo) InvokeDynamic() *InvokeDynamicInfo {
	return nil
}

func (c *ClassInfo) Class() *ClassInfo {
	return c
}

func (c *ClassInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.NameIndex)
}

func (c *ClassInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *FieldrefInfo) Field() *FieldrefInfo {
	return c
}

func (c *FieldrefInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.ClassIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.NameAndTypeIndex); err != nil {
		return err
	}

	return nil
}

func (c *FieldrefInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *MethodrefInfo) Method() *MethodrefInfo {
	return c
}

func (c *MethodrefInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.ClassIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.NameAndTypeIndex); err != nil {
		return err
	}

	return nil
}

func (c *MethodrefInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *InterfaceMethodrefInfo) InterfaceMethod() *InterfaceMethodrefInfo {
	return c
}

func (c *InterfaceMethodrefInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.ClassIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.NameAndTypeIndex); err != nil {
		return err
	}

	return nil
}

func (c *InterfaceMethodrefInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *StringInfo) String() *StringInfo {
	return c
}

func (c *StringInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.StringIndex)
}

func (c *StringInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *IntegerInfo) Integer() *IntegerInfo {
	return c
}

func (c *IntegerInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.Value)
}

func (c *IntegerInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *FloatInfo) Float() *FloatInfo {
	return c
}

func (c *FloatInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.Value)
}

func (c *FloatInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *LongInfo) Long() *LongInfo {
	return c
}

func (c *LongInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.Value)
}

func (c *LongInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *DoubleInfo) Double() *DoubleInfo {
	return c
}

func (c *DoubleInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.Value)
}

func (c *DoubleInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *NameAndTypeInfo) NameAndType() *NameAndTypeInfo {
	return c
}

func (c *NameAndTypeInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.NameIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.DescriptorIndex); err != nil {
		return err
	}

	return nil
}

func (c *NameAndTypeInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *Utf8Info) Utf8() *Utf8Info {
	return c
}

func (c *Utf8Info) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.Length); err != nil {
		return err
	}

	str := make([]uint8, c.Length)
	if err := binary.Read(r, ByteOrder, str); err != nil {
		return err
	}

	c.Value = string(str)

	return nil
}

func (c *Utf8Info) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, c.CpInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, c.Length); err != nil {
		return err
	}

	return binary.Write(w, ByteOrder, []byte(c.Value))
}

func (c *MethodHandleInfo) MethodHandle() *MethodHandleInfo {
	return c
}

func (c *MethodHandleInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.ReferenceKind); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.ReferenceIndex); err != nil {
		return err
	}

	return nil
}

func (c *MethodHandleInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *MethodTypeInfo) MethodType() *MethodTypeInfo {
	return c
}

func (c *MethodTypeInfo) Read(r io.Reader) error {
	return binary.Read(r, ByteOrder, &c.DescriptorIndex)
}

func (c *MethodTypeInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (c *InvokeDynamicInfo) InvokeDynamic() *InvokeDynamicInfo {
	return c
}

func (c *InvokeDynamicInfo) Read(r io.Reader) error {
	if err := binary.Read(r, ByteOrder, &c.BootstrapMethodAttrIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &c.NameAndTypeIndex); err != nil {
		return err
	}

	return nil
}

func (c *InvokeDynamicInfo) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, c)
}

func (constPool ConstantPool) GetClass(index ConstantPoolIndex) *ClassInfo {
	return constPool[index-1].Class()
}

func (constPool ConstantPool) GetField(index ConstantPoolIndex) *FieldrefInfo {
	return constPool[index-1].Field()
}

func (constPool ConstantPool) GetMethod(index ConstantPoolIndex) *MethodrefInfo {
	return constPool[index-1].Method()
}

func (constPool ConstantPool) GetInterfaceMethod(index ConstantPoolIndex) *InterfaceMethodrefInfo {
	return constPool[index-1].InterfaceMethod()
}

func (constPool ConstantPool) GetString(index ConstantPoolIndex) *StringInfo {
	return constPool[index-1].String()
}

func (constPool ConstantPool) GetInteger(index ConstantPoolIndex) int32 {
	return constPool[index-1].Integer().Value
}

func (constPool ConstantPool) GetFloat(index ConstantPoolIndex) float32 {
	return constPool[index-1].Float().Value
}

func (constPool ConstantPool) GetLong(index ConstantPoolIndex) int64 {
	return constPool[index-1].Long().Value
}

func (constPool ConstantPool) GetDouble(index ConstantPoolIndex) float64 {
	return constPool[index-1].Double().Value
}

func (constPool ConstantPool) GetNameAndType(index ConstantPoolIndex) *NameAndTypeInfo {
	return constPool[index-1].NameAndType()
}

func (constPool ConstantPool) GetUtf8(index ConstantPoolIndex) string {
	return constPool[index-1].Utf8().Value
}

func (constPool ConstantPool) GetMethodHandle(index ConstantPoolIndex) *MethodHandleInfo {
	return constPool[index-1].MethodHandle()
}

func (constPool ConstantPool) GetMethodType(index ConstantPoolIndex) *MethodTypeInfo {
	return constPool[index-1].MethodType()
}

func (constPool ConstantPool) GetInvokeDynamic(index ConstantPoolIndex) *InvokeDynamicInfo {
	return constPool[index-1].InvokeDynamic()
}

func (c *ClassFile) GetClassName() string {
	nameIndex := c.ConstantPool[c.ThisClass-1].Class().NameIndex - 1
	return c.ConstantPool[nameIndex].Utf8().Value
}

func (c *ClassFile) GetSuperClassName() string {
	if c.SuperClass > 0 {
		nameIndex := c.ConstantPool[c.SuperClass-1].Class().NameIndex - 1
		return c.ConstantPool[nameIndex].Utf8().Value
	}

	return ""
}

func (c *ClassFile) GetFieldName(field *FieldInfo) string {
	return c.ConstantPool[field.NameIndex-1].Utf8().Value
}

func (c *ClassFile) GetFieldDescriptor(field *FieldInfo) string {
	return c.ConstantPool[field.DescriptorIndex-1].Utf8().Value
}

func (c *ClassFile) GetMethodName(method *MethodInfo) string {
	return c.ConstantPool[method.NameIndex-1].Utf8().Value
}

func (c *ClassFile) GetMethodDescriptor(method *MethodInfo) string {
	return c.ConstantPool[method.DescriptorIndex-1].Utf8().Value
}

func (c *ClassFile) IsInitializer(method *MethodInfo) bool {
	return c.GetMethodName(method) == "<init>"
}

func (c *ClassFile) IsStaticInitializer(method *MethodInfo) bool {
	return c.GetMethodName(method) == "<clinit>"
}

func (c *ClassFile) IsNativeMethod(method *MethodInfo) bool {
	return c.GetMethodName(method) == "(Native Method)"
}

func readAttributes(r io.Reader, constPool ConstantPool) (uint16, []Attribute, error) {
	var count uint16
	if err := binary.Read(r, ByteOrder, &count); err != nil {
		return 0, nil, err
	}

	attrs := make([]Attribute, 0, count)

	for i := uint16(0); i < count; i++ {
		attrBase := AttributeInfo{}

		if err := binary.Read(r, ByteOrder, &attrBase.AttributeNameIndex); err != nil {
			return 0, nil, err
		}

		if err := binary.Read(r, ByteOrder, &attrBase.AttributeLength); err != nil {
			return 0, nil, err
		}

		var attr Attribute
		switch constPool.GetUtf8(attrBase.AttributeNameIndex) {
		case "ConstantValueAttribute":
			attr = &ConstantValueAttribute{AttributeInfo: attrBase}
		case "CodeAttribute":
			attr = &CodeAttribute{AttributeInfo: attrBase}
		case "StackMapTableAttribute":
			attr = &StackMapTableAttribute{AttributeInfo: attrBase}
		case "ExceptionsAttribute":
			attr = &ExceptionsAttribute{AttributeInfo: attrBase}
		case "InnerClassesAttribute":
			attr = &InnerClassesAttribute{AttributeInfo: attrBase}
		case "EnclosingMethodAttribute":
			attr = &EnclosingMethodAttribute{AttributeInfo: attrBase}
		case "SyntheticAttribute":
			attr = &SyntheticAttribute{AttributeInfo: attrBase}
		case "SignatureAttribute":
			attr = &SignatureAttribute{AttributeInfo: attrBase}
		case "SourceFileAttribute":
			attr = &SourceFileAttribute{AttributeInfo: attrBase}
		case "SourceDebugExtensionAttribute":
			attr = &SourceDebugExtensionAttribute{AttributeInfo: attrBase}
		case "LineNumberTableAttribute":
			attr = &LineNumberTableAttribute{AttributeInfo: attrBase}
		case "LocalVariableTableAttribute":
			attr = &LocalVariableTableAttribute{AttributeInfo: attrBase}
		case "LocalVariableTypeTableAttribute":
			attr = &LocalVariableTypeTableAttribute{AttributeInfo: attrBase}
		case "DeprecatedAttribute":
			attr = &DeprecatedAttribute{AttributeInfo: attrBase}
		case "RuntimeVisibleAnnotationsAttribute":
			attr = &RuntimeVisibleAnnotationsAttribute{AttributeInfo: attrBase}
		case "RuntimeInvisibleAnnotationsAttribute":
			attr = &RuntimeInvisibleAnnotationsAttribute{AttributeInfo: attrBase}
		case "RuntimeVisibleParameterAnnotationsAttribute":
			attr = &RuntimeVisibleParameterAnnotationsAttribute{AttributeInfo: attrBase}
		case "RuntimeInvisibleParameterAnnotationsAttribute":
			attr = &RuntimeInvisibleParameterAnnotationsAttribute{AttributeInfo: attrBase}
		case "AnnotationDefaultAttribute":
			attr = &AnnotationDefaultAttribute{AttributeInfo: attrBase}
		case "BootstrapMethodsAttribute":
			attr = &BootstrapMethodsAttribute{AttributeInfo: attrBase}
		default:
			attr = &UnknownAttribute{AttributeInfo: attrBase}
		}

		if err := attr.Read(r, constPool); err != nil {
			return 0, nil, err
		}

		attrs = append(attrs, attr)
	}

	return count, attrs, nil
}

func writeAttributes(w io.Writer, count uint16, attrs []Attribute) error {
	if err := binary.Write(w, ByteOrder, count); err != nil {
		return err
	}

	for _, attr := range attrs {
		if err := attr.Write(w); err != nil {
			return err
		}
	}

	return nil
}

func (a AttributeInfo) ConstantValueAttribute() *ConstantValueAttribute {
	return nil
}

func (a AttributeInfo) CodeAttribute() *CodeAttribute {
	return nil
}

func (a AttributeInfo) StackMapTableAttribute() *StackMapTableAttribute {
	return nil
}

func (a AttributeInfo) ExceptionsAttribute() *ExceptionsAttribute {
	return nil
}

func (a AttributeInfo) InnerClassesAttribute() *InnerClassesAttribute {
	return nil
}

func (a AttributeInfo) EnclosingMethodAttribute() *EnclosingMethodAttribute {
	return nil
}

func (a AttributeInfo) SyntheticAttribute() *SyntheticAttribute {
	return nil
}

func (a AttributeInfo) SignatureAttribute() *SignatureAttribute {
	return nil
}

func (a AttributeInfo) SourceFileAttribute() *SourceFileAttribute {
	return nil
}

func (a AttributeInfo) SourceDebugExtensionAttribute() *SourceDebugExtensionAttribute {
	return nil
}

func (a AttributeInfo) LineNumberTableAttribute() *LineNumberTableAttribute {
	return nil
}

func (a AttributeInfo) LocalVariableTableAttribute() *LocalVariableTableAttribute {
	return nil
}

func (a AttributeInfo) LocalVariableTypeTableAttribute() *LocalVariableTypeTableAttribute {
	return nil
}

func (a AttributeInfo) DeprecatedAttribute() *DeprecatedAttribute {
	return nil
}

func (a AttributeInfo) RuntimeVisibleAnnotationsAttribute() *RuntimeVisibleAnnotationsAttribute {
	return nil
}

func (a AttributeInfo) RuntimeInvisibleAnnotationsAttribute() *RuntimeInvisibleAnnotationsAttribute {
	return nil
}

func (a AttributeInfo) RuntimeVisibleParameterAnnotationsAttribute() *RuntimeVisibleParameterAnnotationsAttribute {
	return nil
}

func (a AttributeInfo) RuntimeInvisibleParameterAnnotationsAttribute() *RuntimeInvisibleParameterAnnotationsAttribute {
	return nil
}

func (a AttributeInfo) AnnotationDefaultAttribute() *AnnotationDefaultAttribute {
	return nil
}

func (a AttributeInfo) BootstrapMethodsAttribute() *BootstrapMethodsAttribute {
	return nil
}

func (a AttributeInfo) UnknownAttribute() *UnknownAttribute {
	return nil
}

func (a *ConstantValueAttribute) ConstantValueAttribute() *ConstantValueAttribute {
	return a
}

func (a *ConstantValueAttribute) GetTag() AttributeType {
	return ConstantValueTag
}

func (a *ConstantValueAttribute) Read(r io.Reader, _ ConstantPool) error {
	return binary.Read(r, ByteOrder, &a.ConstantValueIndex)
}

func (a *ConstantValueAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *CodeAttribute) CodeAttribute() *CodeAttribute {
	return a
}

func (a *CodeAttribute) GetTag() AttributeType {
	return CodeTag
}

func (a *CodeAttribute) Read(r io.Reader, constPool ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.MaxStack); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &a.MaxLocals); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &a.CodeLength); err != nil {
		return err
	}

	a.Code = make([]uint8, a.CodeLength)
	if err := binary.Read(r, ByteOrder, a.Code); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &a.NumberOfExceptions); err != nil {
		return err
	}

	a.ExceptionIndexTable = make([]ExceptionIndexTableValue, a.NumberOfExceptions)
	if err := binary.Read(r, ByteOrder, a.ExceptionIndexTable); err != nil {
		return err
	}

	var err error
	a.AttributesCount, a.Attributes, err = readAttributes(r, constPool)
	return err
}

func (a *CodeAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.MaxStack); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.MaxLocals); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.CodeLength); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.Code); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.NumberOfExceptions); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.ExceptionIndexTable); err != nil {
		return err
	}

	if err := writeAttributes(w, a.AttributesCount, a.Attributes); err != nil {
		return err
	}

	return nil
}

func (a *StackMapTableAttribute) StackMapTableAttribute() *StackMapTableAttribute {
	return a
}

func (a *StackMapTableAttribute) GetTag() AttributeType {
	return StackMapTableTag
}

func (a *StackMapTableAttribute) Read(r io.Reader, _ ConstantPool) error {
	a.Data = make([]uint8, a.AttributeLength)
	return binary.Read(r, ByteOrder, a.Data)
}

func (a *StackMapTableAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.Data); err != nil {
		return err
	}

	return nil
}

func (a *ExceptionsAttribute) ExceptionsAttribute() *ExceptionsAttribute {
	return a
}

func (a *ExceptionsAttribute) GetTag() AttributeType {
	return ExceptionsTag
}

func (a *ExceptionsAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.NumberOfExceptions); err != nil {
		return err
	}

	a.ExceptionIndexTable = make([]ConstantPoolIndex, a.NumberOfExceptions)
	return binary.Read(r, ByteOrder, a.ExceptionIndexTable)
}

func (a *ExceptionsAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.NumberOfExceptions); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.ExceptionIndexTable); err != nil {
		return err
	}

	return nil
}

func (a *InnerClassesAttribute) InnerClassesAttribute() *InnerClassesAttribute {
	return a
}

func (a *InnerClassesAttribute) GetTag() AttributeType {
	return InnerClassesTag
}

func (a *InnerClassesAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.NumberOfClasses); err != nil {
		return err
	}

	a.Classes = make([]InnerClass, a.NumberOfClasses)
	return binary.Read(r, ByteOrder, a.Classes)
}

func (a *InnerClassesAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.NumberOfClasses); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.Classes); err != nil {
		return err
	}

	return nil
}

func (a *EnclosingMethodAttribute) EnclosingMethodAttribute() *EnclosingMethodAttribute {
	return a
}

func (a *EnclosingMethodAttribute) GetTag() AttributeType {
	return EnclosingMethodTag
}

func (a *EnclosingMethodAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.ClassIndex); err != nil {
		return err
	}

	if err := binary.Read(r, ByteOrder, &a.MethodIndex); err != nil {
		return err
	}

	return nil
}

func (a *EnclosingMethodAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *SyntheticAttribute) SyntheticAttribute() *SyntheticAttribute {
	return a
}

func (a *SyntheticAttribute) GetTag() AttributeType {
	return SyntheticTag
}

func (a *SyntheticAttribute) Read(_ io.Reader, _ ConstantPool) error {
	return nil
}

func (a *SyntheticAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *SignatureAttribute) SignatureAttribute() *SignatureAttribute {
	return a
}

func (a *SignatureAttribute) GetTag() AttributeType {
	return SignatureTag
}

func (a *SignatureAttribute) Read(r io.Reader, _ ConstantPool) error {
	return binary.Read(r, ByteOrder, &a.SignatureIndex)
}

func (a *SignatureAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *SourceFileAttribute) SourceFileAttribute() *SourceFileAttribute {
	return a
}

func (a *SourceFileAttribute) GetTag() AttributeType {
	return SourceFileTag
}

func (a *SourceFileAttribute) Read(r io.Reader, _ ConstantPool) error {
	return binary.Read(r, ByteOrder, &a.SourceFileIndex)
}

func (a *SourceFileAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *SourceDebugExtensionAttribute) SourceDebugExtensionAttribute() *SourceDebugExtensionAttribute {
	return a
}

func (a *SourceDebugExtensionAttribute) GetTag() AttributeType {
	return SourceDebugExtensionTag
}

func (a *SourceDebugExtensionAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.DebugExtensionLength); err != nil {
		return err
	}

	str := make([]uint8, a.DebugExtensionLength)
	if err := binary.Read(r, ByteOrder, str); err != nil {
		return err
	}

	a.DebugExtension = string(str)

	return nil
}

func (a *SourceDebugExtensionAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.DebugExtensionLength); err != nil {
		return err
	}

	return binary.Write(w, ByteOrder, []byte(a.DebugExtension))
}

func (a *LineNumberTableAttribute) LineNumberTableAttribute() *LineNumberTableAttribute {
	return a
}

func (a *LineNumberTableAttribute) GetTag() AttributeType {
	return LineNumberTableTag
}

func (a *LineNumberTableAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.LineNumberTableLength); err != nil {
		return err
	}

	a.LineNumberTable = make([]LineNumber, a.LineNumberTableLength)
	return binary.Read(r, ByteOrder, a.LineNumberTable)
}

func (a *LineNumberTableAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LineNumberTableLength); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LineNumberTable); err != nil {
		return err
	}

	return nil
}

func (a *LocalVariableTableAttribute) LocalVariableTableAttribute() *LocalVariableTableAttribute {
	return a
}

func (a *LocalVariableTableAttribute) GetTag() AttributeType {
	return LocalVariableTableTag
}

func (a *LocalVariableTableAttribute) Read(r io.Reader, _ ConstantPool) error {
	err := binary.Read(r, ByteOrder, &a.LocalVariableTableLength)
	if err != nil {
		return err
	}

	a.LocalVariableTable = make([]LocalVariable, a.LocalVariableTableLength)
	return binary.Read(r, ByteOrder, a.LocalVariableTable)
}

func (a *LocalVariableTableAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LocalVariableTableLength); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LocalVariableTable); err != nil {
		return err
	}

	return nil
}

func (a *LocalVariableTypeTableAttribute) LocalVariableTypeTableAttribute() *LocalVariableTypeTableAttribute {
	return a
}

func (a *LocalVariableTypeTableAttribute) GetTag() AttributeType {
	return LocalVariableTypeTableTag
}

func (a *LocalVariableTypeTableAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.LocalVariableTypeTableLength); err != nil {
		return err
	}

	a.LocalVariableTypeTable = make([]LocalVariableType, a.LocalVariableTypeTableLength)
	return binary.Read(r, ByteOrder, a.LocalVariableTypeTable)
}

func (a *LocalVariableTypeTableAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LocalVariableTypeTableLength); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.LocalVariableTypeTable); err != nil {
		return err
	}

	return nil
}

func (a *DeprecatedAttribute) DeprecatedAttribute() *DeprecatedAttribute {
	return a
}

func (a *DeprecatedAttribute) GetTag() AttributeType {
	return DeprecatedTag
}

func (a *DeprecatedAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *DeprecatedAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *RuntimeVisibleAnnotationsAttribute) RuntimeVisibleAnnotationsAttribute() *RuntimeVisibleAnnotationsAttribute {
	return a
}

func (a *RuntimeVisibleAnnotationsAttribute) GetTag() AttributeType {
	return RuntimeVisibleAnnotationsTag
}

func (a *RuntimeVisibleAnnotationsAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *RuntimeVisibleAnnotationsAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *RuntimeInvisibleAnnotationsAttribute) RuntimeInvisibleAnnotationsAttribute() *RuntimeInvisibleAnnotationsAttribute {
	return a
}

func (a *RuntimeInvisibleAnnotationsAttribute) GetTag() AttributeType {
	return RuntimeInvisibleAnnotationsTag
}

func (a *RuntimeInvisibleAnnotationsAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *RuntimeInvisibleAnnotationsAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *RuntimeVisibleParameterAnnotationsAttribute) RuntimeVisibleParameterAnnotationsAttribute() *RuntimeVisibleParameterAnnotationsAttribute {
	return a
}

func (a *RuntimeVisibleParameterAnnotationsAttribute) GetTag() AttributeType {
	return RuntimeVisibleParameterAnnotationsTag
}

func (a *RuntimeVisibleParameterAnnotationsAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *RuntimeVisibleParameterAnnotationsAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *RuntimeInvisibleParameterAnnotationsAttribute) RuntimeInvisibleParameterAnnotationsAttribute() *RuntimeInvisibleParameterAnnotationsAttribute {
	return a
}

func (a *RuntimeInvisibleParameterAnnotationsAttribute) GetTag() AttributeType {
	return RuntimeInvisibleParameterAnnotationsTag
}

func (a *RuntimeInvisibleParameterAnnotationsAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *RuntimeInvisibleParameterAnnotationsAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *AnnotationDefaultAttribute) AnnotationDefaultAttribute() *AnnotationDefaultAttribute {
	return a
}

func (a *AnnotationDefaultAttribute) GetTag() AttributeType {
	return AnnotationDefaultTag
}

func (a *AnnotationDefaultAttribute) Read(r io.Reader, _ ConstantPool) error {
	return nil
}

func (a *AnnotationDefaultAttribute) Write(w io.Writer) error {
	return binary.Write(w, ByteOrder, a)
}

func (a *BootstrapMethodsAttribute) BootstrapMethodsAttribute() *BootstrapMethodsAttribute {
	return a
}

func (a *BootstrapMethodsAttribute) GetTag() AttributeType {
	return BootstrapMethodsTag
}

func (a *BootstrapMethodsAttribute) Read(r io.Reader, _ ConstantPool) error {
	if err := binary.Read(r, ByteOrder, &a.NumBootstrapMethods); err != nil {
		return err
	}

	a.BootstrapMethods = make([]BootstrapMethod, 0, a.NumBootstrapMethods)

	for i := uint16(0); i < a.NumBootstrapMethods; i++ {
		method := BootstrapMethod{}

		if err := binary.Read(r, ByteOrder, &method.BootstrapMethodRef); err != nil {
			return err
		}

		if err := binary.Read(r, ByteOrder, &method.NumBootstrapArguments); err != nil {
			return err
		}

		method.BootstrapArguments = make([]ConstantPoolIndex, method.NumBootstrapArguments)
		if err := binary.Read(r, ByteOrder, method.BootstrapArguments); err != nil {
			return err
		}

		a.BootstrapMethods = append(a.BootstrapMethods, method)
	}

	return nil
}

func (a *BootstrapMethodsAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.NumBootstrapMethods); err != nil {
		return err
	}

	for _, method := range a.BootstrapMethods {
		if err := binary.Write(w, ByteOrder, method.BootstrapMethodRef); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, method.NumBootstrapArguments); err != nil {
			return err
		}

		if err := binary.Write(w, ByteOrder, method.BootstrapArguments); err != nil {
			return err
		}
	}

	return nil
}

func (a *UnknownAttribute) UnknownAttribute() *UnknownAttribute {
	return a
}

func (a *UnknownAttribute) GetTag() AttributeType {
	return UnknownTag
}

func (a *UnknownAttribute) Read(r io.Reader, _ ConstantPool) error {
	a.Data = make([]uint8, a.AttributeLength)
	return binary.Read(r, ByteOrder, a.Data)
}

func (a *UnknownAttribute) Write(w io.Writer) error {
	if err := binary.Write(w, ByteOrder, a.AttributeInfo); err != nil {
		return err
	}

	if err := binary.Write(w, ByteOrder, a.Data); err != nil {
		return err
	}

	return nil
}
