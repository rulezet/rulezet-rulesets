rule asf_file_header_guid__8_byt_16_
{
strings:
	$a0 = { a1dcab8c47a9cf118ee400c00c205365 }

condition:
	$a0
}