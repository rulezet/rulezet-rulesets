rule Pickle_LegacyPyTorch {
	meta:
		author = "Eoin Wickens - Eoin@HiddenLayer.com"
		description = "Detects Legacy PyTorch Pickle files"
		date = "2022-09-16"
	strings:
		$pytorch_legacy_magic_big = {19 50 a8 6a 20 f9 46 9c fc 6c}
		$pytorch_legacy_magic_little = {50 19 6a a8 f9 20 9c 46 6c fc}
	condition:
		uint8(0) == 0x80 and ($pytorch_legacy_magic_little or
			$pytorch_legacy_magic_big in (0..20))
}