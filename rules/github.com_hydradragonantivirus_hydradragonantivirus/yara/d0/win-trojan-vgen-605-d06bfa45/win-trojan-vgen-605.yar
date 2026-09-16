rule Win_Trojan_VGEN_605
{
strings:
	$a0 = { 03908db6bf01bf0001b90400fcf3a4b8ffffcd213d341274508cd8488ed8803e00005a7540a103002d40007238 }


condition:
	$a0
}