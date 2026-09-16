rule Trojan_Win32_Azorult_CD_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 18 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 10 00 00 51 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}