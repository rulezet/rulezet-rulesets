rule telegram_encrypted_file: telegram
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {54 44 45 46}

    condition:
       $a at 0
}