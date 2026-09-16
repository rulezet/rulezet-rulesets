rule apple_dylib: DYLIB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { cf fa ed fe 0c 00 00 01 }

    condition:
	$a at 0
}