rule Ransom_Win32_Filecoder_PAGW_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 04 ?? 31 d1 88 4c 04 ?? 40 83 f8 ?? 7d 09 0f b6 4c 04 ?? 72 e8 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}