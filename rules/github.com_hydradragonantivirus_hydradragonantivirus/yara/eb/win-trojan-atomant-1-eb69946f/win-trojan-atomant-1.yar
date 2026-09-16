rule Win_Trojan_Atomant_1
{
strings:
	$a0 = { 4b743f3dff35740f80fc41740f80fc13740a2eff2eec }


condition:
	$a0
}