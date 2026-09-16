rule Win_Trojan_Pamp_1
{
strings:
	$a0 = { 0683e803a30500b440b9b002ba0000cd21b800422bc92bd2cd21b440b90300ba0400cd21b8 }


condition:
	$a0
}