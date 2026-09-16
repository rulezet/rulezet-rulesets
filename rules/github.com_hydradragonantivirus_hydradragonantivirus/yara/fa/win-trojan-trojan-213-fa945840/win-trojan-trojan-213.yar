rule Win_Trojan_Trojan_213
{
strings:
	$a0 = { f7f27cba7dc74704fdf2a21ed6a0d8f04ff9c050aa36c3176809aef6388f29bfc317838c03faaffa }


condition:
	$a0
}