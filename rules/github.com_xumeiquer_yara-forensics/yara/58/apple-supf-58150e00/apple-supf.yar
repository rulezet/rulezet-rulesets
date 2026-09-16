rule apple_supf: SUPF
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 03 34 30 35 00 00 07 a8 }

    condition:
	$a at 0
}