rule Backdoor_Win64_Mozaakai_MK_MTB_3{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 48 8d 52 ff 42 88 44 31 0c 48 ff c1 48 3b cb 7c ec } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}