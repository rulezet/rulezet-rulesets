rule Win_Trojan_Tuesday_1
{
strings:
	$a0 = { 740649b80143cd21b8023dcd217226 }


condition:
	$a0
}