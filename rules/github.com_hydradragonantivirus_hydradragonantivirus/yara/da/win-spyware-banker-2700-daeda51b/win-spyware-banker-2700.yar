rule Win_Spyware_Banker_2700
{
strings:
	$a0 = { 9361ce58970313b65dbf4765e22659c96ebac1547b55de8dfc7035aff3341b5de4c1aa9788cbcc99514eccf5d31b89866172778990c22e8f9251c3bc6346a3fe2c7ed6ebdda8c6121436fab2dcf4 }


condition:
	$a0
}