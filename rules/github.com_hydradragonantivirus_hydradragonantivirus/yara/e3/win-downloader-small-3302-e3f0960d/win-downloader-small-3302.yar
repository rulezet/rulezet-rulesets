rule Win_Downloader_Small_3302
{
strings:
	$a0 = { f8e51dc07334f240ac2b1a72cfa9d145440a2e50cad7e3a980cfb5d0288590387bac2f9d4793ef5a6a329024fb900592f224f920a80356377ba9 }


condition:
	$a0
}