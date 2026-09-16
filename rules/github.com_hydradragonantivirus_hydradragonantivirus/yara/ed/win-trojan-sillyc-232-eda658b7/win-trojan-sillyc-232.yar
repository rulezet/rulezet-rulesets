rule Win_Trojan_SillyC_232
{
strings:
	$a0 = { ffcd21a30101803dbf7419b800424199cd21b601b162b440cd218bd78b0e0101b440cd21 }


condition:
	$a0
}