rule Trojan_Win32_Glupteba_EA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d7 33 d6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b da 8b 44 24 1c 29 44 24 10 83 6c 24 14 01 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}