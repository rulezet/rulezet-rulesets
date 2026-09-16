rule Trojan_Win32_Qbot_NB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 f2 8d [0-03] 89 [0-05] 8d [0-02] bf [0-04] 2b fe 03 d7 0f [0-06] 03 [0-05] 8b [0-03] 89 [0-05] 8b [0-05] 8d [0-06] 8b [0-02] 0f [0-02] 39 [0-05] 90 18 83 [0-04] 8a c2 b3 11 f6 eb 81 [0-05] 02 c1 81 [0-07] 89 [0-05] 89 [0-02] 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}