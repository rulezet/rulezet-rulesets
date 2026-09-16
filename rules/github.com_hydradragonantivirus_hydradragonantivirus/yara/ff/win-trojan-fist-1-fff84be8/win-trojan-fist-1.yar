rule Win_Trojan_Fist_1
{
strings:
	$a0 = { 33c08ed88ed0bc007c89e5fb83ae138803cd12b106d3e0508ec0b8b2005033dbb90200ba8000b80302cd13cb }


condition:
	$a0
}