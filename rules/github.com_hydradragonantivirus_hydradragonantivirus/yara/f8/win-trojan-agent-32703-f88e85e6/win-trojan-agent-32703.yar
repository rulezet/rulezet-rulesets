rule Win_Trojan_Agent_32703
{
strings:
	$a0 = { 68f3db7566b2e92f8b3de208a6894e279cedd22449bba0a04a1464e65abf513852cc38b7a7b5f3111aa493de02452c82ab3e926bd6d54c7be691c7a92f5fee134fe356f9 }


condition:
	$a0
}