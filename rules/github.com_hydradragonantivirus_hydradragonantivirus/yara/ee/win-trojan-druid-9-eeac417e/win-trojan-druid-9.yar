rule Win_Trojan_Druid_9
{
strings:
	$a0 = { b8023dcd21722693b80057cd215251b440b93701ba9e00cd21595ab80157cd21b43ecd2159 }


condition:
	$a0
}