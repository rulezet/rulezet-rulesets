import "pe"
rule _StarForce_30__StarForce_Technology_
{
	meta:
		description = "StarForce 3.0 -> StarForce Technology"
	strings:
		$0 = {68 ?? ?? ?? ?? FF 25 ?? ?? 63}
	condition:
		$0 at pe.entry_point
}