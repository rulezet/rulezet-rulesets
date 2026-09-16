rule shelltools_g0t_root_resolve {
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "69bf9aa296238610a0e05f99b5540297"
	strings:
		$s0 = "3^n6B(Ed3"
		$s1 = "^uldn'Vt(x"
		$s2 = "\\= uPKfp"
		$s3 = "'r.axV<ad"
		$s4 = "p,modoi$=sr("
		$s5 = "DiamondC8S t"
		$s6 = "`lQ9fX<ZvJW"
	condition:
		all of them
}