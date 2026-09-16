rule Win_Trojan_SillyC_140
{
strings:
	$a0 = { 9003d6b90300b440cd217220b8024233d233c9cd21b9fe0090b4408bd6cd21b801578b8cfc }


condition:
	$a0
}