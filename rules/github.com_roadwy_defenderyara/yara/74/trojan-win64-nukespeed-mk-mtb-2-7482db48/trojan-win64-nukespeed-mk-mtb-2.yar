rule Trojan_Win64_NukeSpeed_MK_MTB_2{
	meta:
		description = "Trojan:Win64/NukeSpeed.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 74 05 f7 [0-01] 80 74 05 f8 90 1b 00 48 83 c0 02 48 83 f8 [0-01] 7c } 		$a_03_1 = {41 0f b6 4c 10 [0-01] 48 ff c2 41 32 cc 48 ff cf 88 4a ff 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}