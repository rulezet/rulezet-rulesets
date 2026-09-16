rule Win_Trojan_Fratz_1
{
strings:
	$a0 = { 53515256571e06b85633cd213dcccc7503e983008cd8488ed8a000003c5a75778b1e0300b44a83eb2ecd21b448bb2d00cd21488ed840c706 }


condition:
	$a0
}