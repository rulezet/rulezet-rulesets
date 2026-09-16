rule Trojan_Win32_Virlock_GMH_MTB{
	meta:
		description = "Trojan:Win32/Virlock.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {40 00 fc 3a 40 00 e8 ?? ?? ?? ?? 5c 40 00 10 3b 40 00 04 3b 40 00 04 5d 40 00 98 38 40 00 d4 38 40 00 } 		$a_01_1 = {6f 45 38 4d 6e 4f 74 } 		$a_01_2 = {50 2e 76 6d 70 30 } 		$a_01_3 = {2e 76 6d 70 31 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}