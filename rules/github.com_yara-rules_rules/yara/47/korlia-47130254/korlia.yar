rule korlia
{ 
meta:
author = "Nick Hoffman" 
company = "Morphick"
reference = "http://www.morphick.com/resources/lab-blog/curious-korlia"
information = "korlia malware found in apt dump" 




strings:
$a = {b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1} 
$b = {B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1} 
$c = {8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1} 
$d = {00 62 69 73 6F 6E 61 6C 00} condition:
any of them 
}