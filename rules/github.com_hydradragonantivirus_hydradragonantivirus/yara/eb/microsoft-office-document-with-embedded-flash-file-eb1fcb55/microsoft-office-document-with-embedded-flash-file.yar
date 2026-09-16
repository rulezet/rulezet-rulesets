rule Microsoft_Office_Document_with_Embedded_Flash_File
{
    strings:
        $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
        $b = { 57 53 }
    condition:
        $a and $b
}