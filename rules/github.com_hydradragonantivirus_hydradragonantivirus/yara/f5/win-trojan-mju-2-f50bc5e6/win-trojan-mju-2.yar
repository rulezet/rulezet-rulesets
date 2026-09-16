rule Win_Trojan_MJU_2
{
strings:
	$a0 = { 02428bcacd2150b440b17ecd21c7054de98f4502b800428bcacd21b440b104cd21b43ecd21 }


condition:
	$a0
}