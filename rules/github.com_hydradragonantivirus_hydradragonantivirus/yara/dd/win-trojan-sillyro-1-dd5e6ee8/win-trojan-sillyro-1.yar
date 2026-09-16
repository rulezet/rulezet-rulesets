rule Win_Trojan_SillyRO_1
{
strings:
	$a0 = { 27cd209c80fcff7504b4559dcf80fc4b751e601eb8013dcd21721393b440ba00010e1fb9c500cd }


condition:
	$a0
}