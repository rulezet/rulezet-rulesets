rule SEH__v3 : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}