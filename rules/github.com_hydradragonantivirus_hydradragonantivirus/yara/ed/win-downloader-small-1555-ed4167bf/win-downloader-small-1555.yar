rule Win_Downloader_Small_1555
{
strings:
	$a0 = { 31c083ec0831c9890c240f010c248b0c2485c974eb83c408e8000000005a83ea1d81ea }


condition:
	$a0
}