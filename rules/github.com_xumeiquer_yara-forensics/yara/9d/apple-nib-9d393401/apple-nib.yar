rule apple_nib: NIB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 4e 49 42 41 72 63 68 69 76 65 01 }

    condition:
	$a at 0
}