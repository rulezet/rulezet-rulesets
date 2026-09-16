rule Trojan_Win32_CerberCrypt_CMX_MTB_2{
	meta:
		description = "Trojan:Win32/CerberCrypt.CMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 90 46 47 49 90 83 f9 00 } 		$a_01_1 = {8a 06 32 c2 90 88 07 90 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}