rule Win_Trojan_SillyC_151
{
strings:
	$a0 = { e93e88860d02b440b903008d960d02cd21b8024233c92bd23e8b9e0702cd21b440b911013e8b9e }


condition:
	$a0
}