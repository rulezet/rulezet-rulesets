rule Trojan_Win64_Cobaltstrike_DL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 4d 8d 40 01 49 83 fa 15 49 0f 45 ca 41 ff c1 42 0f b6 04 19 4c 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}