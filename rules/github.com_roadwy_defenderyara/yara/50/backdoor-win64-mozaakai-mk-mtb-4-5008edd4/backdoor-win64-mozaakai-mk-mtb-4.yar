rule Backdoor_Win64_Mozaakai_MK_MTB_4{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0a 48 8d 52 ff 42 88 4c 30 0c 48 ff c0 48 3b c7 7c ec } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}