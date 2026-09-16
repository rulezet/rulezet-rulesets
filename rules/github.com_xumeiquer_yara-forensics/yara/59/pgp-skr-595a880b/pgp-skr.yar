rule pgp_skr: PGP SKR
{
    meta:
        author = "Jaume Martin"
        description = "Private keyring"
    strings:
        $a = {95 00}
        $b = {95 01}

    condition:
       $a at 0 or $b at 0
}