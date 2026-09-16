rule Win_Trojan_Babylonia_1
{
strings:
	$a0 = { c4e6fc2bc0e8090000008b642408e9fb02000064ff30648920bef800f7bf8b3681eee8ff08 }


condition:
	$a0
}