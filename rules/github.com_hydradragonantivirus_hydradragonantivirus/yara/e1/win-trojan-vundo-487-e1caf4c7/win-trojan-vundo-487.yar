rule Win_Trojan_Vundo_487
{
strings:
	$a0 = { e2838bf82bd9b298ff106bda97b7a9588d140ab6a6ff10b7c02bdac343000000e898f9ffffc300 }


condition:
	$a0
}