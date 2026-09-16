rule asf_content_desc_guid__8_byt_16_
{
strings:
	$a0 = { 3326b2758e66cf11a6d900aa0062ce6c }

condition:
	$a0
}