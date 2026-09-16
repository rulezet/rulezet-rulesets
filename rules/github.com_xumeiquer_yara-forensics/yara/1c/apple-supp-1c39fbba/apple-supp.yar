rule apple_supp: SUPP
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 01 34 30 35 2b 8d 5c 4c 24 18 d2 5f }

    condition:
	$a at 0
}