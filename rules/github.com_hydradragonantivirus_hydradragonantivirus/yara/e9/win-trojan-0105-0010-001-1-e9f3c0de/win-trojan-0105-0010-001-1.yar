rule Win_Trojan__0105_0010_001_1
{
strings:
	$a0 = { 03017405b91c00eb03b90300b440ba4a03cd21b801572e8b0e46032e8b16480380c91fcd21b43e }


condition:
	$a0
}