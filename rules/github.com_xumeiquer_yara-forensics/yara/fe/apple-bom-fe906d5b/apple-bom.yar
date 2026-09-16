rule apple_bom: CAR
{
    meta:
        author = "Joan Bono"

    strings:
	$a = { 42 4f 4d 53 74 6f 72 65 }

    condition:
       $a at 0
}