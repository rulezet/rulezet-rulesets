rule Trojan_Win32_Bunitucrypt_RTA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 ?? 04 8b ?? ?? 83 c0 04 89 ?? ?? 8b ?? ?? 3b ?? ?? 72 [0-05] c7 ?? ?? 00 10 00 00 8b ?? ?? 03 ?? ?? 2b ?? ?? 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}