rule telegram_file: telegram
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {54 44 46 24}

    condition:
       $a at 0
}