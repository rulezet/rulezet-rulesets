rule latro_stealer_module {
    meta:
        description = "Detects Latrodectus Stealer Module"
		author = "The DFIR Report, RussianPanda"
		id = "4d75f691-f467-4284-8774-a3202f375262"
		reference = "https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion"
        date = "2025-09-01"
        hash = "7f04fffad5549592c3d2baaa9c893ba046e94f7c83c9b5be4cc2d507245c4d86"
    strings:
        $s1 = "cr_pass"
		$s2 = "ff_pass"
		$s3 = "ie_pass"
		$s4 = "edge_pass"
		$s5 = "outlook_pass"
		$s6 = "edge_pass"
    condition:
        all of them
}