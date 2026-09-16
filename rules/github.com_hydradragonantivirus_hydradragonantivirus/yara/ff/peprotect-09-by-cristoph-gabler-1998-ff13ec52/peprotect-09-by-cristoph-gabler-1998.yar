rule _PEProtect_09_by_Cristoph_Gabler_1998_
{
	meta:
		description = "PE-Protect 0.9 by Cristoph Gabler 1998"
	strings:
		$0 = {50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39}
	condition:
		$0
}