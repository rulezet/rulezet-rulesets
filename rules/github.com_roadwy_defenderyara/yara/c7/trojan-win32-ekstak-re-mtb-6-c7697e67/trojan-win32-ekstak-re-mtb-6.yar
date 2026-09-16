rule Trojan_Win32_Ekstak_RE_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 71 69 4c 00 68 a4 30 4c 00 ff 15 3c 10 4c 00 50 e8 74 0d fd ff b9 41 00 00 00 33 c0 bf 00 65 4c 00 f3 ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}