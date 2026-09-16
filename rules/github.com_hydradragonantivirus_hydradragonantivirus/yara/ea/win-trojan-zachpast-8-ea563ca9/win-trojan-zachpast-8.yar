rule Win_Trojan_Zachpast_8
{
strings:
	$a0 = { 524547454449542e455845202f532074726f666b7a2e524547 }

	$a1 = { 6e657473746174202d65 }


condition:
	$a0 and $a1
}