import "pe"
rule _SOFTWrapper_for_Win9xNT_Evaluation_Version_
{
	meta:
		description = "SOFTWrapper for Win9x/NT (Evaluation Version)"
	strings:
		$0 = {6A ?? E8 ?? ?? A3}
	condition:
		$0 at pe.entry_point
}