rule quartus_database: QRDB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 51 75 61 72 74 75 73 5F 56 65 72 73 69 6F 6E 20 }

    condition:
	$a at 0
}