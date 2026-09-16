rule Win_Spyware_Banker_3062
{
strings:
	$a0 = { abe8e6951ea8669c659f0eae6990ddf4fc382d79cc7e6274c1fc39e97ca68dcbd13e677b5b991e0932518b7195aa141edc934e8d43bc46a3569132b780b8 }


condition:
	$a0
}