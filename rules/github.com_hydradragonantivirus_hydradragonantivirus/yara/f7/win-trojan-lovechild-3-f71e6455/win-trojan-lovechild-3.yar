rule Win_Trojan_LoveChild_3
{
strings:
	$a0 = { b80102bb0010b90100ba0000cd13721fba0001b90300b80103cd137212bb4001b90100ba0000b80103cd137202cd20b8070ecd10cd20 }


condition:
	$a0
}