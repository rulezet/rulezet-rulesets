rule Trojan_Win32_Emotet_CD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 ec 1c 8b 45 08 89 45 f8 8b 45 0c 89 45 fc 8b 45 fc 8b 00 89 45 f4 8b 45 f8 8b 00 89 45 f0 8b 45 f0 8a 00 88 45 ef } 		$a_81_1 = {77 21 53 6c 65 55 2b 2b 51 68 42 6d 72 46 4a 39 53 4a 5f 52 43 5e 66 4f 29 32 55 78 4e 35 4d 6c 4e 46 39 53 29 67 30 30 66 66 48 32 37 2a 69 78 45 46 4b 2a 58 26 25 4b 5e 40 65 6c 56 38 4c 74 49 25 50 43 6b 32 6f 2a 31 52 2b 63 36 2a 74 78 32 48 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*5) >=15
 
}