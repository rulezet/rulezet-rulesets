rule Win_Trojan_Face_1
{
strings:
	$a0 = { 2dff212ef550fd7c6cc110462c61513c297194e92284892d8d818cf77ec4796ba9cb0118e466b3ae }


condition:
	$a0
}