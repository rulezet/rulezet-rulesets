rule Win_Trojan_Vgen_153
{
strings:
	$a0 = { 5a0000000000000000bad001b44ecd21e81300bac201b44ecd21e80900ba6f01b409cd21cd20721dba9e00b8013dcd }


condition:
	$a0
}