rule b374k
{
    meta:
        author = "Blair Gillam (@blairgillam)"

    strings:
        $string = "b374k"
        $password_var = "$s_pass"
        $default_password = "0de664ecd2be02cdd54234a0d1229b43"

    condition:
        any of them
}