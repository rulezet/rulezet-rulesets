rule Ransom_Win32_Phobos_A{
	meta:
		description = "Ransom:Win32/Phobos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 33 c0 89 5d d4 8d 7d d8 ab ab 33 c0 89 5d c4 8d 7d c8 ab ab 33 c0 89 5d b8 8d 7d bc ab 8d b6 ?? ?? ?? ?? 89 5d f0 89 5d f4 89 5d e0 ab } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}