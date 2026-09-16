rule Win_Trojan_Ultimate_2
{
strings:
	$a0 = { 415757bee7018005c6474e75f9c34576696cdfd2cd0c8fdf5de33e8ce6582fd19fe97feb38834268f6365a7bf82f }


condition:
	$a0
}