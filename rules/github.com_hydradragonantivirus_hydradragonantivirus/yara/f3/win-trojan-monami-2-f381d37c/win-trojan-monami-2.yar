rule Win_Trojan_Monami_2
{
strings:
	$a0 = { fcffb9ffffb80142e87e0190b440e8510173afeb6b8b4408a300032bd2e86101b106b440e84701 }


condition:
	$a0
}