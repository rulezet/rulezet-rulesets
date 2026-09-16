rule Win_Trojan_Sality_1049
{
strings:
	$a0 = { 5f??8a44050050583007fec95e4e0f855cfeffff }


condition:
	$a0
}