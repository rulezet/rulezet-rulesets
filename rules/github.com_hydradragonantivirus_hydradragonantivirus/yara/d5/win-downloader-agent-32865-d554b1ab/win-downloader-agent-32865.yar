rule Win_Downloader_Agent_32865
{
strings:
	$a0 = { ab0d0d91ad19062e9097b37e8ee6052ba57ddaa0e818d35f3d7ccdbd7947cd4efe8adf00f77091e1e5055f94a761a0689ccac8dfbcf182bcda3cf1845cc7 }


condition:
	$a0
}