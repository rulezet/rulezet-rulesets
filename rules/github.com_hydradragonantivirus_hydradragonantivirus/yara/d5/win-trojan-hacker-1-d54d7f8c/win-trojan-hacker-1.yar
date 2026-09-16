rule Win_Trojan_Hacker_1
{
strings:
	$a0 = { 4bcd2172151e0e1f8bf783ee0301 }


condition:
	$a0
}