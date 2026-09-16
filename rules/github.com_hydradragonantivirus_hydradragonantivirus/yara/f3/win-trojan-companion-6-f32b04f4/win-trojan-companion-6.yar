rule Win_Trojan_Companion_6
{
strings:
	$a0 = { cd2190bf830190891d908c450290ba220190b42590cd219089fa90cd27903d004b90755a }


condition:
	$a0
}