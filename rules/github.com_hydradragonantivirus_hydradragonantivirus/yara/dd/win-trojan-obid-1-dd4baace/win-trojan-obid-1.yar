rule Win_Trojan_Obid_1
{
strings:
	$a0 = { 8bd681c20001b92b02cd21e82800b4408bd681c21001b90300cd212e8f840f012e8f840d015a }


condition:
	$a0
}