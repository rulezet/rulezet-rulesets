rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}