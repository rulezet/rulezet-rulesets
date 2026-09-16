rule Win_Trojan_Vundo_423
{
strings:
	$a0 = { 558bec538b5d08568b750c85f6578b7d107500eb3d57495395afc16bcd87b90385df311bbdb729b375 }


condition:
	$a0
}