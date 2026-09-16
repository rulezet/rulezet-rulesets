rule IronTiger_PlugX_DosEmulator
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro - modified by Florian Roth"
		description = "Iron Tiger Malware - PlugX DosEmulator"
		reference = "http://goo.gl/T5fSJC"
		id = "e601d91d-49e6-5fe9-b70b-fb1fb6c4f059"
	strings:
		$str1 = "Dos Emluator Ver" wide ascii
		$str2 = "\\PIPE\\FASTDOS" wide ascii
		$str3 = "FastDos.cpp" wide ascii
		$str4 = "fail,error code = %d." wide ascii
	condition:
		uint16(0) == 0x5a4d and 2 of ($str*)
}