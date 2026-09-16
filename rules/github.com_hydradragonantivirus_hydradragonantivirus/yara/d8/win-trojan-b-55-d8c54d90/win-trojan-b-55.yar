rule Win_Trojan_B_55
{
strings:
	$a0 = { 0102ba0000b90100cd135b730880fc0674eceb6c9081fe5aa574658cc80500105350cd12bb40 }


condition:
	$a0
}