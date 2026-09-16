rule Win_Trojan_SKIM1455_1
{
strings:
	$a0 = { 422bc999cd218a0eec0153bb0100d3e38bcb5bf7f189f7033eea018905c74502a505c7450480 }


condition:
	$a0
}