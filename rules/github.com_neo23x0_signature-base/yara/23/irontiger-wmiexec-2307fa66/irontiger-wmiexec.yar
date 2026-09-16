rule IronTiger_wmiexec
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Tool - wmi.vbs detection"
		reference = "http://goo.gl/T5fSJC"
		id = "a3060f50-3594-5da9-98e2-6fa0087451f5"
	strings:
		$str1 = "Temp Result File , Change it to where you like" wide ascii
		$str2 = "wmiexec" wide ascii
		$str3 = "By. Twi1ight" wide ascii
		$str4 = "[both mode] ,delay TIME to read result" wide ascii
		$str5 = "such as nc.exe or Trojan" wide ascii
		$str6 = "+++shell mode+++" wide ascii
		$str7 = "win2008 fso has no privilege to delete file" wide ascii
	condition:
		2 of ($str*)
}