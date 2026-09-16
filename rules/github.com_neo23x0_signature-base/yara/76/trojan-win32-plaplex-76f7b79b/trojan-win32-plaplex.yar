rule Trojan_Win32_Plaplex : Platinum
{
	meta:
		author = "Microsoft"
		description = "Variant of the JPin backdoor"
		original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
		unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"

		id = "2d670c09-dc0a-556e-8d00-5f94e5907d99"
	strings:
		$class_name1 = "AVCObfuscation"
		$class_name2 = "AVCSetiriControl"

	condition:
		$class_name1 and $class_name2
}