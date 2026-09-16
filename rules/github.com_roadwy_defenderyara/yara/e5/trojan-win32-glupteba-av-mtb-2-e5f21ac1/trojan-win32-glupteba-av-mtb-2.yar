rule Trojan_Win32_Glupteba_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 6c 75 0b b8 56 c4 08 00 01 05 ?? ?? ?? ?? 41 81 f9 0f 7e 49 00 7c e7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}