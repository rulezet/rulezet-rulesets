import "pe"
rule Windows_9x_User_password_file: PEiD
{
    strings:
        $a = { E3 82 85 96 }
    condition:
        $a at pe.entry_point

}