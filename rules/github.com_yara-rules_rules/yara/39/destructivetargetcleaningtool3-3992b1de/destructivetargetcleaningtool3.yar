rule DestructiveTargetCleaningTool3
{
	
	strings:
		$S1_CMD_Arg = "/install" fullword
		$S2_CMD_Parse= "\"%s\"  /install \"%s\"" fullword
		$S3_CMD_Builder= "\"%s\"  \"%s\" \"%s\" %s" fullword
	
	condition:
		all of them
}