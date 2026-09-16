rule SUSP_netsh_firewall_command : pe {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"

	strings:
		$netsh_delete = "netsh firewall delete" wide
		$netsh_add = "netsh firewall add" wide

	condition:
		uint16(0) == 0x5a4d
		and filesize < 100KB
		and ($netsh_delete or $netsh_add)
}