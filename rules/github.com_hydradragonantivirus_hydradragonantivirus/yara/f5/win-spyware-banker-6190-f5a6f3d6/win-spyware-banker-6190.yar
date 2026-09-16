rule Win_Spyware_Banker_6190
{
strings:
	$a0 = { f68901f67d98b7a5553bdc20f4009f436d9e5af2dcef009a2dae93d5059b3a007a5e36e72bcee5a000fa756966e610a2 }


condition:
	$a0
}