rule Win_Trojan_Startpage_500
{
strings:
	$a0 = { 558becb9050000006a006a004975f953b87cb845 }

	$a1 = { 66745c496e7465726e6574204578706c6f7265725c4d61696e }

	$a2 = { 53746172742050616765 }


condition:
	$a0 and $a1 and $a2
}