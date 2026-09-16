rule rule_saint_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'saint' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saint"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_saint_offensive_tool_keyword = /\%appdata\%\\\(s\)AINT/ nocase ascii wide
                        $string2_saint_offensive_tool_keyword = /\/sAINT\.git/ nocase ascii wide
                        $string3_saint_offensive_tool_keyword = /\/sAINT\-master\.zip/ nocase ascii wide
                        $string4_saint_offensive_tool_keyword = /\:\:\sRemove\s\(s\)AINT\sfolder/ nocase ascii wide
                        $string5_saint_offensive_tool_keyword = /\\\(s\)AINT\\Cam/ nocase ascii wide
                        $string6_saint_offensive_tool_keyword = /\\\(s\)AINT\\Logs/ nocase ascii wide
                        $string7_saint_offensive_tool_keyword = /\\\(s\)AINT\\saint\.jar/ nocase ascii wide
                        $string8_saint_offensive_tool_keyword = /\\\(s\)AINT\\Screenshot/ nocase ascii wide
                        $string9_saint_offensive_tool_keyword = /\\\\saint\.jar/ nocase ascii wide
                        $string10_saint_offensive_tool_keyword = /\\AppData\\Local\\Temp\\factura\.exe/ nocase ascii wide
                        $string11_saint_offensive_tool_keyword = /\\sAINT\-master\.zip/ nocase ascii wide
                        $string12_saint_offensive_tool_keyword = /\]\sEnable\sPersistence\s\(Y\/n\)\:\s/ nocase ascii wide
                        $string13_saint_offensive_tool_keyword = /\]\sYou\swould\slike\sto\sgenerate\s\.EXE\susing\slauch4j\?\s\(y\/n\)\:/ nocase ascii wide
                        $string14_saint_offensive_tool_keyword = /AppData\\Roaming\\\(s\)AINT/ nocase ascii wide
                        $string15_saint_offensive_tool_keyword = /import\sorg\.jnativehook\.keyboard\.NativeKeyListener/ nocase ascii wide
                        $string16_saint_offensive_tool_keyword = /import\ssaint\.email\.SendEmail/ nocase ascii wide
                        $string17_saint_offensive_tool_keyword = /import\ssaint\.screenshot\.Screenshot/ nocase ascii wide
                        $string18_saint_offensive_tool_keyword = /import\ssaint\.webcam\.Cam/ nocase ascii wide
                        $string19_saint_offensive_tool_keyword = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
                        $string20_saint_offensive_tool_keyword = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
                        $string21_saint_offensive_tool_keyword = /Keylogger\.java/ nocase ascii wide
                        $string22_saint_offensive_tool_keyword = /launch4j\slaunch4j\/sAINT\.xml/ nocase ascii wide
                        $string23_saint_offensive_tool_keyword = /package\ssaint\.keylogger/ nocase ascii wide
                        $string24_saint_offensive_tool_keyword = /package\ssaint\.webcam/ nocase ascii wide
                        $string25_saint_offensive_tool_keyword = "public class Keylogger" nocase ascii wide
                        $string26_saint_offensive_tool_keyword = /REG\sADD\sHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\s\/V.{0,1000}saint\.jar/ nocase ascii wide
                        $string27_saint_offensive_tool_keyword = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\sSecurity\s\/f/ nocase ascii wide
                        $string28_saint_offensive_tool_keyword = /sAINT.{0,1000}launch4j\.tar\.xz/ nocase ascii wide
                        $string29_saint_offensive_tool_keyword = /sAINT\\lib\\activation\.jar/ nocase ascii wide
                        $string30_saint_offensive_tool_keyword = /saint\-1\.0\-jar\-with\-dependencies\.exe/ nocase ascii wide
                        $string31_saint_offensive_tool_keyword = /saint\-1\.0\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string32_saint_offensive_tool_keyword = "tiagorlampert/sAINT" nocase ascii wide
                        $string33_saint_offensive_tool_keyword = /ui\\sAINT\.java/ nocase ascii wide
                        $string34_saint_offensive_tool_keyword = /webcam\-capture\-0\.3\.10\.jar/ nocase ascii wide

    condition:
        any of them
}