rule Win_Trojan_Bancos_1807
{
strings:
	$a0 = { ec87b11b7393c8dd6131cde696192ac2d8915759dd27cbec6549d1748bdc100a5eb0f0dc417fabd5a1213cbda589db89cb5d53ac1f1ea6261bbfa562352d9eb044f06ec426df }


condition:
	$a0
}