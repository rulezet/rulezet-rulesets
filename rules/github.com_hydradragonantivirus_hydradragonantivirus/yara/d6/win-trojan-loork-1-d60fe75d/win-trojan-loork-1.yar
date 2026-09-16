rule Win_Trojan_Loork_1
{
strings:
	$a0 = { 6b7230306c2e }

	$a1 = { 206279205b77617267616d652c23656f665d }

	$a2 = { 2e696e64657828666c2c222e66652229 }


condition:
	$a0 and $a1 and $a2
}