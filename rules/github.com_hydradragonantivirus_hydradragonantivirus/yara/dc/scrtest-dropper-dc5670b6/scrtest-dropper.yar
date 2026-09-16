rule scrtest_dropper {
    strings:
                $export = "SCRTEST\x00"
        $decrypt_key = "EEB0F\x00"
        $main = { C645E44DC645E561C645E669C645E76EC645E800 }
        
    condition:
        uint16be(0) == 0x4d5a and (($export and $decrypt_key) or $main)
}