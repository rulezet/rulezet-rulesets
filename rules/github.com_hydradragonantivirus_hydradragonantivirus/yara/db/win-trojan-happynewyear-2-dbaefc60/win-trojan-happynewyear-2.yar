rule Win_Trojan_HappyNewYear_2
{
strings:
	$a0 = { e81cfd72ef50b91000f7f15052b9 }


condition:
	$a0
}