rule apple_sinf: SINF
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 00 00 04 20 73 69 6e 66 }

    condition:
	$a at 0
}