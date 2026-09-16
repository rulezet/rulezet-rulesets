rule Win_Trojan_Druid_6
{
strings:
	$a0 = { ba9e00b8023dcd21722693b80057cd215251b440b93501ba9e00cd21595ab80157cd21b43ecd2159 }


condition:
	$a0
}