rule Win_Trojan_SillyC_26
{
strings:
	$a0 = { 59ba6d01b44ecd217249ba9e00b8023dcd218bd8498cc880c4108ed833d2b43fcd212e8b3600013b35741c5041b8 }


condition:
	$a0
}