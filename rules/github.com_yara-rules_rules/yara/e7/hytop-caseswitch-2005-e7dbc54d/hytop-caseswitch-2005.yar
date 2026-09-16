rule HYTop_CaseSwitch_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"
	condition:
		all of them
}