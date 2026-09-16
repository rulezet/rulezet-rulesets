rule Win_Trojan_Realize_1
{
strings:
	$a0 = { cd21b000e84400b440b9f201ba0001cd21b002e83500b440b9f2018bd5cd215a59b80157cd21 }


condition:
	$a0
}