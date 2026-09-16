rule Win_Trojan_Andromeda_5
{
strings:
	$a0 = { 03e9b3fd80fc30750981fea3b47503bfcabdfb2eff }


condition:
	$a0
}