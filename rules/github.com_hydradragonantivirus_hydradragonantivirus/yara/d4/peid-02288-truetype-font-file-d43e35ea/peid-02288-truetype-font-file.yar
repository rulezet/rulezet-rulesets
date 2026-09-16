rule PEiD_02288_TrueType_Font_file_
{
    meta:
        description = "[TrueType Font file]"
        ep_only = "false"
    strings:
        $a = {00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4F 53 2F 32}
    condition:
        $a
}