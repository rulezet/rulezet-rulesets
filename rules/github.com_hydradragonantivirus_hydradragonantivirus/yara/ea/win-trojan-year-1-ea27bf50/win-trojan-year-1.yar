rule Win_Trojan_Year_1
{
strings:
	$a0 = { 317503eb0f9080fc4c7503eb0790 }


condition:
	$a0
}