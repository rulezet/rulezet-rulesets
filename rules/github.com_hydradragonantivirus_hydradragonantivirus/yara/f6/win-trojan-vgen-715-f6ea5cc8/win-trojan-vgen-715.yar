rule Win_Trojan_VGEN_715
{
strings:
	$a0 = { 8ed8be0301e8a2032bdb8ec3268e061600be03018bfee87d03740c8ec3268e062600e871037548bee8e6e87d03be }


condition:
	$a0
}