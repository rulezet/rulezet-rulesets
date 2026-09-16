rule Win_Spyware_Goldun_90
{
strings:
	$a0 = { 312e6bc03e6b79003908fb2d6c6162731d32db02ffde9e076c697665a2648c65dadb6f61a11f727506776170304472598b4b6c }


condition:
	$a0
}