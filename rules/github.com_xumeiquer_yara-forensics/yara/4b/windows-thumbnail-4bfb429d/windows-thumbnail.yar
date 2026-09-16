rule windows_thumbnail: WTBDB
{
    meta:
        author = "Joan Bono"

    strings:
	$a = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
       $a at 0
}