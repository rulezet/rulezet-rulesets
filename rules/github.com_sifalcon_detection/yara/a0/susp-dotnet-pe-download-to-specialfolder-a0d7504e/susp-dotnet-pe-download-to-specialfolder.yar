import "pe"
rule SUSP_DOTNET_PE_Download_To_SpecialFolder : dotnet download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a .NET Binary that downloads further payload and retrieves a special folder"

	strings:
		$special_folder = "Environment.SpecialFolder" wide

		$webclient = "WebClient()" wide
		$download = ".DownloadFile(" wide

	condition:
		uint16(0) == 0x5a4d 
		and filesize < 100KB 
		and pe.imports("mscoree.dll")
		and $special_folder 
		and $webclient 
		and $download
}