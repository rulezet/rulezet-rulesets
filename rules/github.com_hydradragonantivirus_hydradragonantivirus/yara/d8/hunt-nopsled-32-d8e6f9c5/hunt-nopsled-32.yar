rule HUNT_nopsled_32 {
	meta:
		description = "Matches 32 repeated no-operation hex bytes - 0x90"
		last_modified = "2024-02-18"
		author = "@petermstewart"
		DaysofYara = "49/100"

	strings:
		$a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		filesize < 5MB and
		$a
}