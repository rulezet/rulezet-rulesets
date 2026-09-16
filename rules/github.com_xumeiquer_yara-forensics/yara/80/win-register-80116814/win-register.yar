rule win_register: REG SUD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {52 45 47 45 44 49 54}

    condition:
       $a at 0
}