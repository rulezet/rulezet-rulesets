rule Win_Trojan_ARCV_25
{
strings:
	$a0 = { 8ebf1e02ba90018906c3c307a9e1fbc08dbc1d01b9a30280350347e2fac3 }


condition:
	$a0
}