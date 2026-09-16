rule Win_Trojan_Trivial_263
{
strings:
	$a0 = { ba2801b44ecd21721dba9e00b8013dcd2193b440b92c00ba0001cd21b43ecd21b44fcd21ebe1 }


condition:
	$a0
}