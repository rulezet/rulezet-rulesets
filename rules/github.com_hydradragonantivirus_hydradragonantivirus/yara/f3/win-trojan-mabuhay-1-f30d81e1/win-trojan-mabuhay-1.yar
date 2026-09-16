rule Win_Trojan_Mabuhay_1
{
strings:
	$a0 = { ffd791b3329f01e60aaad1b3335e1b9b2b21eb5e392d2534942b2a7c2d95412c92212bd88f34e0a7eb }


condition:
	$a0
}