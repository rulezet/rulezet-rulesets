rule Win_Downloader_63721_1
{
strings:
	$a0 = { bbba37a62381c3452d7ecc53b845bfba2181c013999d3650ffd4b898d5000081c069aa3f0050b816 }


condition:
	$a0
}