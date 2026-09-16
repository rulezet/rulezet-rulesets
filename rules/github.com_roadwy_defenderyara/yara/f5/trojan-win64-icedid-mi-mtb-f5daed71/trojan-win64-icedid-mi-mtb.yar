rule Trojan_Win64_IcedID_MI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c2 4d 8d 5b 01 48 8b c7 41 ff c2 49 f7 e0 48 c1 ea ?? 48 6b ca ?? 4c 2b c1 42 0f b6 44 84 20 41 30 43 ff 41 81 fa ?? ?? ?? ?? 72 d2 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}