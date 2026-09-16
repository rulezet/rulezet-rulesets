rule Win_Spyware_Banker_2372
{
strings:
	$a0 = { 98e5eab4ab2cfe85735abcc79a66001d979adb59c32818453d539151dd01441b716738debea22ecb7453b236c3469fc3e6d692756af3779ce73908e40dd416c993e794b0cdf04db5cd2c }


condition:
	$a0
}