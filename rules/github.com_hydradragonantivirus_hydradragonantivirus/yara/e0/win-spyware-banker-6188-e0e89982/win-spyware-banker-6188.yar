rule Win_Spyware_Banker_6188
{
strings:
	$a0 = { f8c55778b312a418ac478a404e6939746d0046411b85cbb668021ed04013e68ce04ee8c4c726758a80174bcbbe2447ae }


condition:
	$a0
}