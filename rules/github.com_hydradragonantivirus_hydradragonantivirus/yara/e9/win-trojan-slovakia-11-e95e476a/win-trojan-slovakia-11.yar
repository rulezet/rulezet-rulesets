rule Win_Trojan_Slovakia_11
{
strings:
	$a0 = { 80fa03731a8bd681c24801b409cd21b401b520cd10b486b92000baff0fcd1580bc84010275188c }


condition:
	$a0
}