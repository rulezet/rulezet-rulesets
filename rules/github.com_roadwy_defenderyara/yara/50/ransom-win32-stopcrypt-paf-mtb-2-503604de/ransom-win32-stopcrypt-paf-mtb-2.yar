rule Ransom_Win32_StopCrypt_PAF_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PAF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 55 } 		$a_01_1 = {c2 0c 00 81 00 03 35 ef c6 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}