rule Trojan_Win32_Raccoon_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 83 65 fc 00 8b 45 0c [0-02] 01 45 fc 8b 45 08 8b 4d 0c 31 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}