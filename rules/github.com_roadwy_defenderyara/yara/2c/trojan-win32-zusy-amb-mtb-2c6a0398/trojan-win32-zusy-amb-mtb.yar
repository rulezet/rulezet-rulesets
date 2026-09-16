rule Trojan_Win32_Zusy_AMB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c8 6b c9 0d 02 ca 32 88 ?? ?? ?? ?? 88 4c 05 a0 40 83 f8 59 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}