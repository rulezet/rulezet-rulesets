rule Win_Trojan_VGEN_604
{
strings:
	$a0 = { 1703b800008ed8a14c002ea31c012ea31e01c7064c0024018c0e4e002ea11401b90602f7e18bc82ec6070043e2f9ba }


condition:
	$a0
}