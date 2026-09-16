rule Win_Trojan_DosInfo_1
{
strings:
	$a0 = { 9a0000cd079a000051079a151024045589e5b800019adf04cd0781ec0001c606542a00bf4c2a1e57bf4e2a1e57bf502a }


condition:
	$a0
}