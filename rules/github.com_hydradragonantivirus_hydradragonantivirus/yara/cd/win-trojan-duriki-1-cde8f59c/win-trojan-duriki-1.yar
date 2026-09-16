rule Win_Trojan_Duriki_1
{
strings:
	$a0 = { 9e00b8023dcd217213909093b99800ba9801b440cd21b43ecd21ebd8cd202a2e636f6d000d0a }


condition:
	$a0
}