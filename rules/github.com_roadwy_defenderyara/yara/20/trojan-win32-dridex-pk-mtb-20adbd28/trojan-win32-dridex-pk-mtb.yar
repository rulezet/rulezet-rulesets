rule Trojan_Win32_Dridex_PK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 c1 83 64 [0-03] a2 [0-04] 6b [0-02] 89 [0-03] 2b d8 8a [0-03] 2a [0-05] 89 [0-05] 04 30 8b [0-06] 80 [0-02] 02 [0-03] 81 [0-05] 89 [0-05] a2 [0-04] 88 [0-05] 89 [0-05] 89 [0-06] 83 [0-02] 8b [0-05] 8d [0-02] 0f [0-02] 8b cd 89 [0-03] 81 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}