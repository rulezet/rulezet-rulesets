rule Win_Trojan_Sneeker_1
{
strings:
	$a0 = { 14538bd880ff3d741381fb004b740a5b2eff2e }


condition:
	$a0
}