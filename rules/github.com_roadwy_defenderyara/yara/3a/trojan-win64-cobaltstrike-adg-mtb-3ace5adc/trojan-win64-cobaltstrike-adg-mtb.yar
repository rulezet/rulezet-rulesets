rule Trojan_Win64_Cobaltstrike_ADG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 37 64 61 53 2e 64 6c 6c } 		$a_01_1 = {80 74 05 cf fa 49 03 c4 48 83 f8 0d 72 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}