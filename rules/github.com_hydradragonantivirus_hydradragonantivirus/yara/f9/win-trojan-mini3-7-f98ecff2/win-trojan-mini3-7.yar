rule Win_Trojan_Mini3_7
{
strings:
	$a0 = { 0d90e98b0190902eff1e8c009c3cff742d909050561e2e8b3638022e8e1e3a02803cff750383c6078a4417241f90 }


condition:
	$a0
}