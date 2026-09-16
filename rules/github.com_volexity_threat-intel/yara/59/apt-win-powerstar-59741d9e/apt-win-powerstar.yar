rule apt_win_powerstar : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        description = "Custom PowerShell backdoor used by Charming Kitten."
        date = "2021-10-13"
        hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $appname = "[AppProject.Program]::Main()" ascii wide 
        $langfilters1 = "*shar*" ascii wide
        $langfilters2 = "*owers*" ascii wide

        $definitions1 = "[string]$language" ascii wide
        $definitions2 = "[string]$Command" ascii wide
        $definitions3 = "[string]$ThreadName" ascii wide
        $definitions4 = "[string]$StartStop" ascii wide

        $sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

    condition:
        $appname or
        all of ($langfilters*) or
        all of ($definitions*) or
        $sess
}