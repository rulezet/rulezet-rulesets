rule Win_Spyware_Banker_5878
{
strings:
	$a0 = { 08b4692ef23077fd46fa2d1668c8838cacffb7bd57a0a0c54eb0aeeffceac40ce46bf8064d07e0924b0942da4657b4954e25c2ebc1b6c6be15c4e8dead20098febb77511 }


condition:
	$a0
}