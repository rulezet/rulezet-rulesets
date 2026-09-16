rule Win_Trojan_Jags_2
{
strings:
	$a0 = { e800005d83ed033e8b868501a300013e8a868701a20201b8d0f1cd213dadde7505 }


condition:
	$a0
}