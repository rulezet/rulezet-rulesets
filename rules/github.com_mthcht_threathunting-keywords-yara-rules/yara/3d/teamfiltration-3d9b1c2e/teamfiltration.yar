rule TeamFiltration
{
    meta:
        description = "Detection patterns for the tool 'TeamFiltration' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TeamFiltration"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-config\s.{0,1000}\.json\s\-\-debug\s\-\-exfil\s\-\-onedrive/ nocase ascii wide
                        $string2 = /\s\-\-config\s.{0,1000}\.json\s\-\-enum\s\-\-validate\-msol\s\-\-usernames\s/ nocase ascii wide
                        $string3 = /\s\-\-config\s.{0,1000}\.json\s\-\-enum\s\-\-validate\-teams/ nocase ascii wide
                        $string4 = /\s\-\-config\s.{0,1000}\.json\s\-\-exfil\s\-\-aad/ nocase ascii wide
                        $string5 = " --debug --exfil --onedrive" nocase ascii wide
                        $string6 = " --enum --validate-msol " nocase ascii wide
                        $string7 = " --enum --validate-teams" nocase ascii wide
                        $string8 = /\s\-\-exfil\s\-\-cookie\-dump\s\s.{0,1000}\s\-\-all/ nocase ascii wide
                        $string9 = " --exfil --cookie-dump " nocase ascii wide
                        $string10 = " --exfil --teams --owa --owa-limit" nocase ascii wide
                        $string11 = " --exfil --teams --owa" nocase ascii wide
                        $string12 = /\s\-\-exfil\s\-\-tokens\s.{0,1000}\s\-\-onedrive\s\-\-owa/ nocase ascii wide
                        $string13 = /\s\-\-exfil\s\-\-tokens\s.{0,1000}\s\-\-onedrive/ nocase ascii wide
                        $string14 = /\sloginAAD\.ps1/ nocase ascii wide
                        $string15 = /\s\-\-outpath\s.{0,1000}\s\-\-config\s.{0,1000}\.json\s\-\-backdoor/ nocase ascii wide
                        $string16 = /\s\-\-outpath\s.{0,1000}\.json\s\-\-backdoor/ nocase ascii wide
                        $string17 = /\s\-\-shuffle\-users.{0,1000}\s\-\-spray/ nocase ascii wide
                        $string18 = /\s\-\-spray\s.{0,1000}\-\-shuffle\-users/ nocase ascii wide
                        $string19 = " --spray --passwords " nocase ascii wide
                        $string20 = " --spray --push-locked --months-only --exclude " nocase ascii wide
                        $string21 = " --spray --push-locked --months-only" nocase ascii wide
                        $string22 = /\sTeamFiltration\.dll/ nocase ascii wide
                        $string23 = /\sTeamFiltration\.exe/ nocase ascii wide
                        $string24 = "\"sacrificialO365Passwords\": " nocase ascii wide
                        $string25 = "\"sacrificialO365Username\": " nocase ascii wide
                        $string26 = /\/loginAAD\.ps1/ nocase ascii wide
                        $string27 = /\/TeamFiltration\.dll/ nocase ascii wide
                        $string28 = /\/TeamFiltration\.exe/ nocase ascii wide
                        $string29 = "/TeamFiltration/releases/latest" nocase ascii wide
                        $string30 = /\[\!\]\sCould\snot\sextract\suseful\stoken\sfrom\sspecified\sTeams\sdatabase\!/ nocase ascii wide
                        $string31 = /\[\!\]\sESTSAUTHPERSISTENT\scookie\swas\sempty\!/ nocase ascii wide
                        $string32 = /\[\!\]\sFailed\sto\sexfiltrate\susing\sRoadTools\sauth\sfile/ nocase ascii wide
                        $string33 = /\[\!\]\sFailed\sto\sparse\sRoadTools\sauth\sJSON\sfile/ nocase ascii wide
                        $string34 = /\[\!\]\sThe\sexfiltration\smodules\sdoes\snot\suse\sFireProx/ nocase ascii wide
                        $string35 = /\[\!\]\sYou\sare\srunning\sTeamFiltration\swithout\sa\sconfig/ nocase ascii wide
                        $string36 = /\[\+\]\sCould\snot\sfind\sTeamFiltration\sconfig/ nocase ascii wide
                        $string37 = /\[\+\]\sSuccessfully\sretrieved\san\saccess\stoken\sfor\sUser\:/ nocase ascii wide
                        $string38 = /\\CookieData\.txt\s\-\-all/ nocase ascii wide
                        $string39 = /\\loginAAD\.ps1/ nocase ascii wide
                        $string40 = /\\Modules\\Backdoor\.cs/ nocase ascii wide
                        $string41 = /\\TeamFiltration\.dll/ nocase ascii wide
                        $string42 = /\\TeamFiltration\.exe/ nocase ascii wide
                        $string43 = /\\TeamFiltration\\OneDriveAPI/ nocase ascii wide
                        $string44 = /\\TeamFiltration\\TeamFiltration\\/ nocase ascii wide
                        $string45 = /\\TeamFiltrationConfig_Example\.json/ nocase ascii wide
                        $string46 = /\]\sTeamFiltration\sV3\.5\.3\sPUBLIC/ nocase ascii wide
                        $string47 = /\>TeamFiltration\.dll\</ nocase ascii wide
                        $string48 = "2659c2d40606e2b088c3bbd6fd6a293692ac7f219221844071abf434a638e1da" nocase ascii wide
                        $string49 = "4e09f3d552d00f6ade653b2a9c289a411062b14fab2148f7accab8c8428c9bdb" nocase ascii wide
                        $string50 = "A0F044C5-D910-4720-B082-58824E372281" nocase ascii wide
                        $string51 = "EF143476-E53D-4C39-8DBB-A6AC7883236C" nocase ascii wide
                        $string52 = "Flangvik/TeamFiltration" nocase ascii wide
                        $string53 = /OutputTokens\.txt\s\-\-onedrive\s\-\-owa/ nocase ascii wide
                        $string54 = /raw\.githubusercontent\.com\/Flangvik\/statistically\-likely\-usernames\// nocase ascii wide
                        $string55 = /TeamFiltration\.exe\s/ nocase ascii wide
                        $string56 = /TeamFiltration\\Program\.cs/ nocase ascii wide
                        $string57 = /TeamFiltration\-v.{0,1000}\-linux\-x86_64\.zip/
                        $string58 = /TeamFiltration\-v.{0,1000}\-macOS\-arm64\.zip/ nocase ascii wide
                        $string59 = /TeamFiltration\-v.{0,1000}\-macOS\-x86_64\.zip/ nocase ascii wide
                        $string60 = /TeamFiltration\-v.{0,1000}\-win\-x86_64\.zip/ nocase ascii wide

    condition:
        any of them
}