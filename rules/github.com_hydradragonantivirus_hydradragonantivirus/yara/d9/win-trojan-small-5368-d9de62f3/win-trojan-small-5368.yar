rule Win_Trojan_Small_5368
{
strings:
	$a0 = { 5850eb0033c094946862abe5d75933c0e80000000058689b }


condition:
	$a0
}