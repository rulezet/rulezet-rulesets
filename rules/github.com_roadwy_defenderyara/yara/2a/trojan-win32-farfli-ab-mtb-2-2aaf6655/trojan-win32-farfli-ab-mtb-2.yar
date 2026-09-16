rule Trojan_Win32_Farfli_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 2a 2c 0a 00 68 38 ?? 0d 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 a3 00 00 00 00 58 58 58 58 8b e8 b8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}