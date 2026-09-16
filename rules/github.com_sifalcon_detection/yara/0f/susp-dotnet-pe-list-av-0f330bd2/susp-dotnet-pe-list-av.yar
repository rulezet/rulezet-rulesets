import "pe"
rule SUSP_DOTNET_PE_List_AV : dotnet av {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detecs .NET Binary that lists installed AVs"

	strings:
		$mgt_obj_searcher = "\\root\\SecurityCenter2" wide
		$query = "Select * from AntivirusProduct" wide

	condition:
		uint16(0) == 0x5a4d
		and filesize < 200KB
		and pe.imports("mscoree.dll")
		and $mgt_obj_searcher
		and $query
}