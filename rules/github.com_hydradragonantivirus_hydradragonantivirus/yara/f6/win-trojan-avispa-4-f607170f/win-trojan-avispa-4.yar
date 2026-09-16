rule Win_Trojan_Avispa_4
{
strings:
	$a0 = { bb240188ff80c31688ff2e8b0788edb9881d88ed80e92588ed9033c188f62e890788f683c30288f6b8baf988c005120f }


condition:
	$a0
}