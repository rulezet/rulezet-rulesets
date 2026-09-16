rule Trojan_Win64_IcedID_EH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 74 79 61 73 75 66 61 73 6b 6c 66 6d 6a 6e 61 6b 73 } 		$a_03_1 = {f0 00 22 20 0b 02 ?? ?? 00 78 05 00 00 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}