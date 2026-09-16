rule saint
{
    meta:
        description = "Detection patterns for the tool 'saint' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saint"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\%appdata\%\\\(s\)AINT/ nocase ascii wide
                        $string2 = /\/sAINT\.git/ nocase ascii wide
                        $string3 = /\/sAINT\-master\.zip/ nocase ascii wide
                        $string4 = /\:\:\sRemove\s\(s\)AINT\sfolder/ nocase ascii wide
                        $string5 = /\\\(s\)AINT\\Cam/ nocase ascii wide
                        $string6 = /\\\(s\)AINT\\Logs/ nocase ascii wide
                        $string7 = /\\\(s\)AINT\\saint\.jar/ nocase ascii wide
                        $string8 = /\\\(s\)AINT\\Screenshot/ nocase ascii wide
                        $string9 = /\\\\saint\.jar/ nocase ascii wide
                        $string10 = /\\AppData\\Local\\Temp\\factura\.exe/ nocase ascii wide
                        $string11 = /\\sAINT\-master\.zip/ nocase ascii wide
                        $string12 = /\]\sEnable\sPersistence\s\(Y\/n\)\:\s/ nocase ascii wide
                        $string13 = /\]\sYou\swould\slike\sto\sgenerate\s\.EXE\susing\slauch4j\?\s\(y\/n\)\:/ nocase ascii wide
                        $string14 = /AppData\\Roaming\\\(s\)AINT/ nocase ascii wide
                        $string15 = /import\sorg\.jnativehook\.keyboard\.NativeKeyListener/ nocase ascii wide
                        $string16 = /import\ssaint\.email\.SendEmail/ nocase ascii wide
                        $string17 = /import\ssaint\.screenshot\.Screenshot/ nocase ascii wide
                        $string18 = /import\ssaint\.webcam\.Cam/ nocase ascii wide
                        $string19 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
                        $string20 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
                        $string21 = /Keylogger\.java/ nocase ascii wide
                        $string22 = /launch4j\slaunch4j\/sAINT\.xml/ nocase ascii wide
                        $string23 = /package\ssaint\.keylogger/ nocase ascii wide
                        $string24 = /package\ssaint\.webcam/ nocase ascii wide
                        $string25 = "public class Keylogger" nocase ascii wide
                        $string26 = /REG\sADD\sHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\s\/V.{0,1000}saint\.jar/ nocase ascii wide
                        $string27 = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\sSecurity\s\/f/ nocase ascii wide
                        $string28 = /sAINT.{0,1000}launch4j\.tar\.xz/ nocase ascii wide
                        $string29 = /sAINT\\lib\\activation\.jar/ nocase ascii wide
                        $string30 = /saint\-1\.0\-jar\-with\-dependencies\.exe/ nocase ascii wide
                        $string31 = /saint\-1\.0\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string32 = "tiagorlampert/sAINT" nocase ascii wide
                        $string33 = /ui\\sAINT\.java/ nocase ascii wide
                        $string34 = /webcam\-capture\-0\.3\.10\.jar/ nocase ascii wide

    condition:
        any of them
}