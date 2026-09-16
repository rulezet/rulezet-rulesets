rule Trojan_Win32_Ekstak_RG_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 c7 45 f4 cc cc cc cc c7 45 f8 cc cc cc cc c7 45 fc cc cc cc cc e8 0c 64 fb ff 89 45 fc e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}