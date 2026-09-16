rule vcard: vCard
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {42 45 47 49 4E 3A 56 43 41 52 44 0D 0A}

    condition:
       $a at 0
}