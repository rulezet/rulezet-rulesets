rule Win_Trojan_Uruguay_4
{
strings:
	$a0 = { 6159f9118e0d34ee9d562108a81e69f14d3566f4ba3aa5bf2c27ce8973db8ebd16270adf73ce236df0 }


condition:
	$a0
}