rule pgp_wde: PGP WDE
{
    meta:
        author = "Jaume Martin"
        description = "PGP Whole Disk Encryption"
    strings:
        $a = {50 47 50 64 4D 41 49 4E}

    condition:
       $a at 0
}