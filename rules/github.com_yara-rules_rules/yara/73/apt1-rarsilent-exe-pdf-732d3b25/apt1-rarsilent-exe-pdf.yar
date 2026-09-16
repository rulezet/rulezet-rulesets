rule APT1_RARSilent_EXE_PDF
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $str2 = "Steup=" wide ascii

    condition:
        all of them
}