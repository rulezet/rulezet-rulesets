rule RTF_Byte_Nibble_Obfuscation_method2
{
    strings:
        $magic  = {7b 5c 72}
        $nibble = /\\objupdate.{0,1024}\\objdata.{0,1024}([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){2}/
    condition:
        $magic in (0..30) and all of them
}