rule Win_Trojan_MoonPie_1
{
strings:
	$a0 = { 91f4dd89b6b451498befe5bd8d74358cff7510896980400f6ff097a24ffe66bab7b07823cba6886c07a9451e3c009fcf155be4d224fce803b70853848b407959 }


condition:
	$a0
}