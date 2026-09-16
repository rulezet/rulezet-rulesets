rule Win_Trojan_Hupigon_517
{
strings:
	$a0 = { 144aeece28fdbd37356ebfcf731319a2c90c5ce6f7b459e2e0e2b1c38a2ae4b2073d46f024cedd49e113ea73c76f21cfeb09dc84832dd26505612c46d518aaae1728fd811932fdf7df48a520c76d }


condition:
	$a0
}