rule Win_Trojan__1495_0002_001_1
{
strings:
	$a0 = { 1901720eba1d01b92000b4409c2eff1e19012e8b0e45012e8b164701b801579c2eff1e1901b4 }


condition:
	$a0
}