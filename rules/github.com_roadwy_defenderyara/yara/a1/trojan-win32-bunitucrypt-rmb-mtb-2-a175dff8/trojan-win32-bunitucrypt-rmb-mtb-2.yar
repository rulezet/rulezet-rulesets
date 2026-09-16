rule Trojan_Win32_Bunitucrypt_RMB_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 99 52 50 8b 45 ?? 33 d2 3b 54 24 ?? 75 } 		$a_00_1 = {2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}