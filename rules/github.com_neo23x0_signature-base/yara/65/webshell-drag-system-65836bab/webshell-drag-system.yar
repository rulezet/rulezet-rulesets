rule webshell_drag_system {
	meta:
		description = "Web Shell - file system.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "15ae237cf395fb24cf12bff141fb3f7c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
	condition:
		all of them
}