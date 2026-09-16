rule Win_Trojan_MagicHole_1
{
strings:
	$a0 = { 300446e2fbb440b900028d962b02cd21722d33c8752933c0e4408bc8e5408bd0b440cd21b8 }


condition:
	$a0
}