rule Win_Trojan_VGEN_720
{
strings:
	$a0 = { 1675db65ac4717f01f8937fc1608db65be000156b94f04c704ffc0c6440211813416444646e2f831f631c9c300 }


condition:
	$a0
}