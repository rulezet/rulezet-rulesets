rule Win_Trojan_Xrce_2
{
strings:
	$a0 = { 89e58b6efafb4d4dfcb80c0ccd212d49487403e84e00b462cd218ec38edb8cc839d8742383c3102e019e43002e03 }


condition:
	$a0
}