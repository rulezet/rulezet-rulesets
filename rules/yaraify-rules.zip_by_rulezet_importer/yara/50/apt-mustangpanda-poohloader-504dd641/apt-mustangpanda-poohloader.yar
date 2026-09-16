rule apt_mustangpanda_poohloader
{
	meta:
		version = "1.0"
		author = "FatzQatz"
		description = "Detect PoohLoader, a Loader used by Mustang Panda to deploy Toneshell. This Loader utilized Mavinject to inject the shellcode."
		date = "2025-01-26"
		yarahub_reference_link = "https://x.com/FatzQatz/status/1883443770819248130"
		last_modified = "2025-01-26"
		yarahub_reference_md5 = "831fded4d56f7e1b04ad4384245ce874"
		yarahub_uuid = "cffc425e-baa3-4c69-a732-27e0e39f4b8e"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		falsepositives= "Unknown"
	strings:
		$s_1 = "C:\\Windows\\SysWOW64\\waitfor.exe" nocase wide
		$s_2 = "c:\\windows\\System32\\regsvr32.exe" nocase wide
		$s_3 = "C:\\Windows\\SysWOW64\\Mavinject.exe" nocase wide
		$s_4 = "DllRegisterServer" nocase
		$s_5 = "INJECTRUNNING" nocase wide
		$hex = {
			8B 45 F8						2B 45 EC						8B 4D EC						8A 90 ?? ?? ?? ??				88 91 ?? ?? ?? ??				8B 45 F8						2B 45 EC						8A 4D E3						88 88 ?? ?? ?? ??		}
	condition:
		uint16(0) == 0x5A4D
		and (filesize >= 400KB and filesize <= 8MB)
		and (all of ($s_*)
			or (any of ($s_*) and $hex))
}