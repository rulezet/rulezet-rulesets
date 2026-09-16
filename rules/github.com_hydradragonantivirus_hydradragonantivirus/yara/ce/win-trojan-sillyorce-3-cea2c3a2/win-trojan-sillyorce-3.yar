rule Win_Trojan_SillyORCE_3
{
strings:
	$a0 = { 4233c999cd21b9b100b440ba0001cd219933c933d2b80157cd21b43ecd21b409ba7601cd21 }


condition:
	$a0
}