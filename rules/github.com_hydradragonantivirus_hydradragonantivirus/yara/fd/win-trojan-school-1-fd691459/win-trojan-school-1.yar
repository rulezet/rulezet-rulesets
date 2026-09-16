rule Win_Trojan_School_1
{
strings:
	$a0 = { 040053bb860203df2e8807432e88275bb440b98e01ba040103d7cd21b80042b90000ba0000cd21 }


condition:
	$a0
}