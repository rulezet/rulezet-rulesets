rule Trojan_Win64_NukeSpeed_MK_MTB{
	meta:
		description = "Trojan:Win64/NukeSpeed.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 04 [0-01] 48 ff c0 42 32 [0-03] 48 83 f8 [0-01] 48 0f 44 c1 41 88 14 18 49 ff c0 49 83 f8 [0-01] 7c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}