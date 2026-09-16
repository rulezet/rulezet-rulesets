rule Win_Trojan_Mgn_1
{
strings:
	$a0 = { 602e8b851f003dff007413be420003f7b9be092e00 }


condition:
	$a0
}