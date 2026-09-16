rule Win_Trojan_Autorun_408
{
strings:
	$a0 = { 5256575053f8510f83b9ffffffbd880540285e0f838ffefffff8ff12 }

	$a1 = { 6b726e6c2e666e72 }


condition:
	$a0 and $a1
}