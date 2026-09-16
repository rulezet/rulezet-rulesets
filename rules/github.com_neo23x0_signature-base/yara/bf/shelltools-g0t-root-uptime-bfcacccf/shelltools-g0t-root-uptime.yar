rule shelltools_g0t_root_uptime {
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
		id = "4f649757-9502-5640-bc17-11cad6c779f4"
	strings:
		$s0 = "JDiamondCSlC~"
		$s1 = "CharactQA"
		$s2 = "$Info: This file is packed with the UPX executable packer $"
		$s5 = "HandlereateConso"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}