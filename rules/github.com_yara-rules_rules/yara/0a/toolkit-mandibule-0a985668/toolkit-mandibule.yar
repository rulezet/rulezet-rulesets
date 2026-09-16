rule TOOLKIT_Mandibule {
	meta:
		description = "Generic detection for ELF Linux process injector mandibule generic"
		reference = "https://imgur.com/a/MuHSZtC"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-06-01"
	condition:
		((is__str_mandibule_gen1) or (is__hex_mid_mandibule32))
		or ((is__str_mandibule_gen1) or (is__hex_top_mandibule64))
		and is__elf
		and filesize < 30KB 
}