rule Win_Trojan_CyberTech_16
{
strings:
	$a0 = { 5d81ed0600508dbe1b008bf7b9e301ac3415aae2fa3b9e93ef143b9e8be9143bb615143b9c0b1714a13fd83495 }


condition:
	$a0
}