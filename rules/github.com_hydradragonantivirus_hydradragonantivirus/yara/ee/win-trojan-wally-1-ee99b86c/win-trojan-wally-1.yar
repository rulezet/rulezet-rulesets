rule Win_Trojan_Wally_1
{
strings:
	$a0 = { b821348b0e00cd2bc88bd19103d35352c3a335ff730c }


condition:
	$a0
}