rule Win_Trojan_KSV_1
{
strings:
	$a0 = { 5152061e9c2ec6064b0301e86bff2e8f06ef02062e8f063400b82135cd218cc02ea3e7022e891ee902b90800bf60 }


condition:
	$a0
}