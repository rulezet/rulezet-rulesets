rule Win_Trojan_Childsplay_1
{
strings:
	$a0 = { 32c0e84300b440b903008d96ad02cd21b002e8330053e817005bb4408d960301b9ab01cd }


condition:
	$a0
}