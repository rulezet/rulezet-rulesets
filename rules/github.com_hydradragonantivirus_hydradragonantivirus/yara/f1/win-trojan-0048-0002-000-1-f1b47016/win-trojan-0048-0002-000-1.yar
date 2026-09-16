rule Win_Trojan__0048_0002_000_1
{
strings:
	$a0 = { e8af005b5803c1f7d832e403c8b440cd210e1f72152bc8751133d2b80042cd21ba9b02b903 }


condition:
	$a0
}