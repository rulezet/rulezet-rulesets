rule Win_Trojan_Shadow_3
{
strings:
	$a0 = { ee0c90bb2f00902e8b542d902e8b0033c22e890083c3 }


condition:
	$a0
}