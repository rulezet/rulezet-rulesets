rule Win_Trojan_Small_146
{
strings:
	$a0 = { 4b754253521eb8023dcd217235930e1fb43f99b904 }


condition:
	$a0
}