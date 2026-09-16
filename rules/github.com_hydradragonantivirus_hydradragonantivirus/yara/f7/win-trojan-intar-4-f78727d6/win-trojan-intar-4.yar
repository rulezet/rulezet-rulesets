rule Win_Trojan_Intar_4
{
strings:
	$a0 = { 60e8000000008b2c2481ed0620400083c4048db5282040008bfeb9b5070000908a06ac }


condition:
	$a0
}