rule Trojan_Win32_Fareit_JNK_MTB{
	meta:
		description = "Trojan:Win32/Fareit.JNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 00 04 46 01 71 01 b1 05 21 01 11 07 00 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}