rule MAL_ELF_TorchTriton {
	meta:
		author = "Silas Cutler"
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		date = "2023-01-02"
		version = "1.0"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		reference = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		DaysofYARA = "2/100"

		id = "85e98ee7-30bf-554f-a0ac-9df263e6dfe4"
	strings:
		$error = "failed to send packet"
		$aes_key = "gIdk8tzrHLOM)mPY-R)QgG[;yRXYCZFU"
		$aes_iv = "?BVsNqL]S.Ni"
					$func01 = "splitIntoDomains("
		$func02 = "packageForTransport"
		$func03 = "gatherFiles"
					$func04 = "void sendFile("
				$domain = "&z-%`-(*"
	condition:
		uint32(0) == 0x464c457f and (
			(all of ($aes_*)) or
			(all of ($func*) and $error) or
			($domain and 2 of them)
			)
}