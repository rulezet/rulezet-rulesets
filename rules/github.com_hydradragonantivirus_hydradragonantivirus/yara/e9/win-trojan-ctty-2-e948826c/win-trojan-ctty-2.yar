rule Win_Trojan_CTTY_2
{
strings:
	$a0 = { 0b00ba5602b92a00b440cd21c3ba4802b90e00b440cd21c3b90b00eb03b90500ba3d02b440cd21 }


condition:
	$a0
}