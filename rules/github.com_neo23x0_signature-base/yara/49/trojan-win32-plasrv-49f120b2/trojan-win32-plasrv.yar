rule Trojan_Win32_PlaSrv : Platinum
{
	meta:
		author = "Microsoft"
		description = "Hotpatching Injector"
		original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
		unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"

		id = "2a099b68-fb13-5926-8a86-4d788326609c"
	strings:
		$Section_name = ".hotp1"
		$offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }
	
	condition:
		$Section_name and $offset_x59
}