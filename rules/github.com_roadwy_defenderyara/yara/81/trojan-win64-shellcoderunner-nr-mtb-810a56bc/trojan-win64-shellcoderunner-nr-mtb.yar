rule Trojan_Win64_ShellcodeRunner_NR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 47 5e 22 fa 19 41 28 8d d0 72 aa 46 b7 aa 85 b8 3b 38 85 1a } 		$a_01_1 = {80 32 f1 45 b7 ff 4d 56 5e eb 17 bb 74 ea 1c db a3 3d 74 37 74 b0 fa 56 be bf 87 d6 c4 cd } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}