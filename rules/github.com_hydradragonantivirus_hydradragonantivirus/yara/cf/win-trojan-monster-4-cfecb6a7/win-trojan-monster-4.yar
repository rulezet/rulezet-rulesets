rule Win_Trojan_Monster_4
{
strings:
	$a0 = { feeb00c606200100b82425ba4202cd21b44732d2be4902cd21eb45fe061901b41aba8902cd21803e19010175 }


condition:
	$a0
}