rule Win_Trojan_B_79
{
strings:
	$a0 = { b90700bb0002ba8000cd138a16040052c606040080bebe03bfbe01b94201 }


condition:
	$a0
}