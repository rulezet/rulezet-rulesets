rule Trojan_Win32_Filecoder_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 52 8b 4d 08 8b 55 0c 81 31 ?? ?? ?? ?? f7 11 83 c1 04 4a 75 f2 5a 59 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}