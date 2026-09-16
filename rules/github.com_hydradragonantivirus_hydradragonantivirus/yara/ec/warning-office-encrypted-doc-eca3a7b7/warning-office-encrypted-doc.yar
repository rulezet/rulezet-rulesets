rule warning_office_encrypted_doc {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 1
        revision = "1"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "office encrypted document"
    strings:
        $s1 = {4D006900630072006F0073006F0066007400200042006100730065002000430072007900700074006F0067007200610070006800690063002000500072006F0076006900640065007200200076}
        $s2 = {45006E006300720079007000740065006400530075006D006D006100720079}
    condition:
        1 of them
}