rule MonitoringTool_AndroidOS_Dromon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 04 11 04 d8 04 [0-02] ff 23 [0-03] 05 12 [0-02] 12 [0-02] 34 [0-02] 07 00 71 10 [0-03] 00 0c 04 28 f3 39 [0-02] 07 00 44 [0-02] 07 [0-02] d8 [0-03] 01 28 f3 d8 04 [0-02] ff 44 05 07 [0-02] d0 55 80 00 d4 [0-02] 80 00 b1 65 d4 55 80 00 8e 55 50 05 [0-01] 04 28 ef } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}