rule win_hive: REG HIVE
{
        meta:
            author = "Jaume Martin"
        strings:
            $a = { 72 65 67 66 }
        condition:
            $a at 0
}