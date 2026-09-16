rule E2_values__32_lil_AND_
{
strings:
	$a0 = { 01234567[0-20]89abcdef[0-20]582ed330[0-20]84499eb8[0-20]eccf5709[0-20]2e5000d8[0-20]00ffff00[0-20]ffff0000[0-20]ff0000ff[0-20]0000ffff[0-20]ff00ff00 }

condition:
	$a0
}