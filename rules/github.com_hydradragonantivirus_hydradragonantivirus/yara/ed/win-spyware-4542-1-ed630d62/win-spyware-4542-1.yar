rule Win_Spyware_4542_1
{
strings:
	$a0 = { 6056891c242b0c2483c40461e858020000933690bb5494d50e5f0e693609 }


condition:
	$a0
}