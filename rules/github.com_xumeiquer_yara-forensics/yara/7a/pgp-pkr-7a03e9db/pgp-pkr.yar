rule pgp_pkr: PGP PKR
{
    meta:
        author = "Jaume Martin"
        description = "Public keyring"
    strings:
        $a = {99 01}

    condition:
       $a at 0
}