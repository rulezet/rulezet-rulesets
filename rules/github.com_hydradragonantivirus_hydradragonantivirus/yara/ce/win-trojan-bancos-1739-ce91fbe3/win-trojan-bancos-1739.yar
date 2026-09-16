rule Win_Trojan_Bancos_1739
{
strings:
	$a0 = { 598091eda74249c761b9c6d0e485f536360ab13a407da9d28e4cb5ad6191f4642069d1dcda2f171275fdda49b1079cc98f7b0e1527ebe1085a1b6bdca35d3d49d1f90ea2c8de }


condition:
	$a0
}