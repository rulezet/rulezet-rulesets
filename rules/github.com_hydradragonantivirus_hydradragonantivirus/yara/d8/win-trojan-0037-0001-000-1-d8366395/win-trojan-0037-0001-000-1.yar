rule Win_Trojan__0037_0001_000_1
{
strings:
	$a0 = { 068db60801e86b005d5b8d96a106b440cd218f860402b80042e82b008d96ff01b90500b440cd }


condition:
	$a0
}