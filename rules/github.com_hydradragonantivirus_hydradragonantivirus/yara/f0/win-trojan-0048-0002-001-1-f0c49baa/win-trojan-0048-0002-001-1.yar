rule Win_Trojan__0048_0002_001_1
{
strings:
	$a0 = { 33d2b80042cd21ba9b02b90300b440cd21595ab80157cd21b43ecd21e92cffb003cf2a2e2a }


condition:
	$a0
}