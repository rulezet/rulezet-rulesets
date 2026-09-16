rule PUA_VULN_Renamed_Driver_Zemanaltd_Zam_E428 {
	meta:
		description = "Detects renamed vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - zam64.sys, zamguard32.sys, zamguard64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "e428ddf9afc9b2d11e2271f0a67a2d6638b860c2c12d4b8cc63d33f3349ee93f"
		date = "2024-08-07"
		score = 70
		id = "354a2208-ec68-59b6-98a0-617ab82f5779"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005a0041004d } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005a0065006d0061006e00610020004c00740064002e } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e00310037002e003900380034 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005a0041004d } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]005a0065006d0061006e00610020004c00740064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them and not filename matches /zam64/i and not filename matches /zamguard32/i and not filename matches /zamguard64/i
}