import "pe"
rule _PECompact_2x_beta_version__Jeremy_Collake_
{
	meta:
		description = "PECompact 2.x (beta version) -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? 00 80 00 28 40}
	condition:
		$0 at pe.entry_point
}