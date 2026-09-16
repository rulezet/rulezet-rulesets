rule Win_Trojan_Genocide_3
{
strings:
	$a0 = { 8b9c860481c60e01b97803d1e973014e8bfead33c3abe2fa5f5e595b58c3e84dfe89958604e8d1ffb440b9d5038d950301cd21e8c3ffc35d8bc55d81ed06018bfd8be8558befc3 }


condition:
	$a0
}