rule Win_Trojan_P1_7
{
strings:
	$a0 = { 5e83c6c5560e1f81c68200b98000bffd008cda01540b3b540b753ba5a4a5a55fad8bde8bf0 }


condition:
	$a0
}