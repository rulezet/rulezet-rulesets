rule Fidelis_Advisory_cedt370 {
    meta:
        description = "Detects a string found in memory of malware cedt370r(3).exe"
        author = "Florian Roth (Nextron Systems)"
        reference = "http://goo.gl/ZjJyti"
        date = "2015-06-09"
        id = "b5ebf2d7-e3e4-5b3b-a082-417da9c7fda6"
    strings:
        $s0 = "PO.exe" ascii fullword
        $s1 = "Important.exe" ascii fullword
        $s2 = "&username=" ascii fullword
        $s3 = "Browsers.txt" ascii fullword
    condition:
        all of them
}