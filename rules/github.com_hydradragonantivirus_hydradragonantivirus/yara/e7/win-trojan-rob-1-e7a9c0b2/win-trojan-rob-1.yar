rule Win_Trojan_Rob_1
{
strings:
	$a0 = { 7238b80103b90100ba8000bb9401cd137228b30388df023e69018ac3b9f401ba0100bb9401cd26 }


condition:
	$a0
}