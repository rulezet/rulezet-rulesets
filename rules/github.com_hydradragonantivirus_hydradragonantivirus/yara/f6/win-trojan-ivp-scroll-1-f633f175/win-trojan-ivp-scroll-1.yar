rule Win_Trojan_IVP_Scroll_1
{
strings:
	$a0 = { b90700cd217207e80500b44febf5c3b8003de82d01b4 }


condition:
	$a0
}