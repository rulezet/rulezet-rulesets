rule PK_Nickel_memoryerror : Nickel
{
    meta:
        description = "Phishing Kit impersonating Nickel"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-24"
        comment = "Phishing Kit - Nickel - 'Main Author: Nawras MemoryError'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "imgs"
        $spec_dir2 = "clients"
        $spec_dir3 = "victims"
                $spec_file = "passe.php"
        $spec_file2 = "control.php"
        $spec_file3 = "style6.css"
        $spec_file4 = "card-back.f1f8eab6.svg"
        $spec_file5 = "Nawras.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}