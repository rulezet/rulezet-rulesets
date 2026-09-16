rule Trojan_Win32_Plapiio : Platinum
{
	meta:
		author = "Microsoft"
		description = "JPin backdoor"
		original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
		unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"

		id = "538086b5-eb06-5e41-90d4-ab8f2b001c42"
	strings:
		$str1 = "ServiceMain"
		$str2 = "Startup"
		$str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

	condition:
		$str1 and $str2 and $str3
}