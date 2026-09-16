rule Win_Trojan_Overkill_2
{
strings:
	$a0 = { cc52b898add252f555e1581be3775ce55e418d623059fc4706f0ba4fc198679e839058a1b23ebab1 }


condition:
	$a0
}