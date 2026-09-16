rule Win_Trojan_RingWorm_2
{
strings:
	$a0 = { 018bfe33db53bb1802b97e00ad73075859abe2f858c33502015a52515087cab8ebffe3fc }


condition:
	$a0
}