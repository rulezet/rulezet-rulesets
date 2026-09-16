rule Win_Trojan_Trojan_167
{
strings:
	$a0 = { 262101581f558bec806606fe5dcf }


condition:
	$a0
}