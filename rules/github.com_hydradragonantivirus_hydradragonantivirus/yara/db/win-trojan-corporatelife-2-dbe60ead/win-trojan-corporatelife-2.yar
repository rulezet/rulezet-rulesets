rule Win_Trojan_CorporateLife_2
{
strings:
	$a0 = { 1dc2f0ce27cd26e233fa82cd74d9339c47203b9acce243ca82cde243ca82cd }


condition:
	$a0
}