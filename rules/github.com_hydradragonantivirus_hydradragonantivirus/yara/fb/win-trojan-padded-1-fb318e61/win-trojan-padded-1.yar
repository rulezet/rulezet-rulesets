rule Win_Trojan_Padded_1
{
strings:
	$a0 = { ba0000cd215a4ab440b90300cd21b80242b90000ba0000cd }


condition:
	$a0
}