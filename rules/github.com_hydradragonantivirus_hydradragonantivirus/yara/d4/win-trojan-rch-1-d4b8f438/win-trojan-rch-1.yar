rule Win_Trojan_Rch_1
{
strings:
	$a0 = { dedc4e6169e19edbcb535153c511cfea950aa5895b730b916ae8ce52a5adb07bc35022005b73dd19 }


condition:
	$a0
}