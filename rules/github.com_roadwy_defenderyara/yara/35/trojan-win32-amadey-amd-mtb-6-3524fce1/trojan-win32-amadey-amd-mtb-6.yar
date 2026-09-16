rule Trojan_Win32_Amadey_AMD_MTB_6{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 d2 2a d0 80 f2 44 2a ca 8a d0 80 f1 af 2a d1 0f b6 c8 d0 ca 2a d0 69 c9 fe 00 00 00 32 d0 f6 d2 80 c2 1a c0 ca 02 80 ea 57 32 d0 2a f2 b2 7d d0 c6 02 f0 f6 de 32 f0 02 f0 80 f6 09 2a ce f6 d1 02 c8 c0 c1 02 f6 d1 32 c8 80 e9 06 c0 c1 02 32 c8 80 c1 25 c0 c9 03 2a c8 d0 c9 80 e9 41 32 c8 80 c1 07 c0 c9 03 80 e9 56 32 c8 02 c8 f6 d9 32 c8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}