rule Win_Trojan_DKiller_1
{
strings:
	$a0 = { 04008d962403cd213e81be240390e975068d86c501 }


condition:
	$a0
}