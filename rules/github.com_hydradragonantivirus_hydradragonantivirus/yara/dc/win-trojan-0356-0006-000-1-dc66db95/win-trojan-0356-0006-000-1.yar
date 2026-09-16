rule Win_Trojan__0356_0006_000_1
{
strings:
	$a0 = { c9e808008bd0b440b90300c39c2eff9e8702c333c08ed88b3604008b1e06008ec3509da1ae00 }


condition:
	$a0
}