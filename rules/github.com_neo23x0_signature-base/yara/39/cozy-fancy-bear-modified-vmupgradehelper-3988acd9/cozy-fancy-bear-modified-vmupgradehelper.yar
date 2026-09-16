rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
	meta:
		description = "Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
		id = "97b844a4-0fa4-5850-8803-2212a69e3d16"
	strings:
		$s1 = "VMware, Inc." wide fullword
		$s2 = "Virtual hardware upgrade helper service" fullword wide
		$s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		filename == "VmUpgradeHelper.exe" and
		not all of ($s*)
}