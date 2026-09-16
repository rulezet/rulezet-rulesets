rule Backdoor_BAT_AsyncRAT_MK_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 13 00 00 06 00 28 06 00 00 06 17 73 2f 00 00 0a 16 14 fe 06 1d 00 00 06 73 30 00 00 0a 73 31 00 00 0a 28 09 00 00 06 00 28 08 00 00 06 28 06 00 00 06 6f 32 00 00 0a } 	condition:
		((#a_01_0  & 1)*35) >=35
 
}