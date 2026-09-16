rule IronTiger_EFH3_encoder
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger EFH3 Encoder"
		reference = "http://goo.gl/T5fSJC"
		id = "ec30782e-8fe9-5843-9db4-5a3c477b7f25"
	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" wide ascii
		$str2 = "123.EXE 123.EFH" wide ascii
		$str3 = "ENCODER: b[i]: = " wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}