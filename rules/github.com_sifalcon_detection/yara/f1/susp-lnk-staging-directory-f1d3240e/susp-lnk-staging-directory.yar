rule SUSP_LNK_Staging_Directory {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects typical staging directories being referenced inside lnk files"

	strings:
		$header = {4c00 0000 0114 0200 0000}
		$public = "$env:public" wide

	condition:
		filesize < 20KB
		and ($header at 0)
		and $public

}