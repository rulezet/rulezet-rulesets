rule Win_Spyware_Banker_2356
{
strings:
	$a0 = { 2e9c250c8cf5e7a9063c2ec3e4003d32c61c320f8143d9acfb3c4289c133058de279ff2b95471d4b9829e3c71e0b2e2f0bd7192b2cc58b27dda198ff08bff2bb7f472a12035a2b0f4aa9 }


condition:
	$a0
}