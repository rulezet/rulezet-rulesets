rule Win_Trojan_Search_17
{
strings:
	$a0 = { 8844ffe2f75e59c306b83335cd2126c607cf07c3b419cd }


condition:
	$a0
}