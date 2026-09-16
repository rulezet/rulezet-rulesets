rule Win_Trojan_Mybot_5550
{
strings:
	$a0 = { ed4bbfccf05991dff1453250c84f1fd4470f2234fd9485f9e2f893547750f951b01be81f581b3087f745ca50737dbeabfc8eb410213da58e846889aba15a38fdb78ce9c5e1d9 }


condition:
	$a0
}