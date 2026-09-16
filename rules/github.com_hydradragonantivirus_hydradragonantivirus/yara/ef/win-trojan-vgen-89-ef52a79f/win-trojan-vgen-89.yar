rule Win_Trojan_VGEN_89
{
strings:
	$a0 = { 80eb009f58bd0400cd038dbec202ffd782240fcd1b8cbc0939f7e9f7e989a40739facddccddcc18dac7f38b81e25f7 }


condition:
	$a0
}