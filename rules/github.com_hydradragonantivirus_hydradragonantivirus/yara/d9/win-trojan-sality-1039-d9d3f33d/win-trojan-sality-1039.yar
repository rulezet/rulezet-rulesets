rule Win_Trojan_Sality_1039
{
strings:
	$a0 = { 02c55f478a4405003007fec95e4e0f85??ffffff }


condition:
	$a0
}