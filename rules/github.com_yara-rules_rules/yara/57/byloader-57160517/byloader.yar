rule byloader {
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f0d6dc26055653f5844ded906ce52df"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"
	condition:
		all of them
}