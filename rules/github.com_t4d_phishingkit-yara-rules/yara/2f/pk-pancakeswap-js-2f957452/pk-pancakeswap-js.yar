rule PK_PancakeSwap_js : PancakeSwap
{
    meta:
        description = "Phishing Kit impersonating PancakeSwap.finance"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-09"
        comment = "Phishing Kit - PancakeSwap - mostly JS"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "_next"
        $spec_dir2 = "oYJ4s4eRSIbPMqWPptiGc"
        $spec_dir3 = "home"

                $spec_file = "popup-6.css"
        $spec_file2 = "_ssgManifest.js"
        $spec_file3 = "7d58cdd3-1068-4b09-a428-7a9c5bd94af4.js"
        $spec_file4 = "wallet-connect-v3.js"
        $spec_file5 = "phishing-warning-bunny.webp"
        $spec_file6 = "rabby-rainbow.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}