rule Backdoor_Win64_Bazarldr_MBK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 f0 48 c1 f8 [0-01] 41 [0-04] 49 [0-03] 48 39 d3 0f 83 [0-04] 48 89 f0 48 c1 f8 [0-01] 41 90 1b 01 49 90 1b 02 48 39 d3 0f 83 [0-04] 48 89 f0 48 83 c6 [0-01] 48 c1 f8 [0-01] 41 90 1b 01 48 83 c3 [0-01] 48 39 df 0f 8e [0-04] 49 90 1b 02 48 39 d3 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}