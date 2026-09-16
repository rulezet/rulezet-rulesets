rule Win_Trojan_Macaroni_4
{
strings:
	$a0 = { e800005db84effcd213d494f74181e06b42ccd2180c5042e882e7501e89500061fe8d700071f2e81be3f044d5a74258db63f04bf0001fca4a4a4a4a433c08bd8 }


condition:
	$a0
}