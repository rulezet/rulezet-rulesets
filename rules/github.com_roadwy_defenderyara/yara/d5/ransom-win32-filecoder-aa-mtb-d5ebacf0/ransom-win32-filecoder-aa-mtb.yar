rule Ransom_Win32_Filecoder_AA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.AA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 20 47 6c 69 74 63 68 42 79 74 65 20 72 61 6e 73 6f 6d 77 61 72 65 } 		$a_01_1 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}