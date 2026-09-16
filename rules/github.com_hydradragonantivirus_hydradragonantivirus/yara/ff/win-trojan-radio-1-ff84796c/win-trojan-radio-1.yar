rule Win_Trojan_Radio_1
{
strings:
	$a0 = { 01cd09488af80a25c94659ae09f9c43734f909627938ce92291709165f080f9ac95e87ceb286083f }


condition:
	$a0
}