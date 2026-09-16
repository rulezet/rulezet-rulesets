rule Win_Trojan_VGEN_498
{
strings:
	$a0 = { 06a3fe0031c08ed8c406ac0031ffb90010e84f0072392e89bf930031f6061fad3d2e8b74034eebf7ac3c9f7403 }


condition:
	$a0
}