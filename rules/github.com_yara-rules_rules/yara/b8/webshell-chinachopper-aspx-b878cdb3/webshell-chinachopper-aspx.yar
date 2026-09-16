rule webshell_ChinaChopper_aspx
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/28"
    description = "Detect China Chopper ASPX webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "aspx"
  strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
  condition:
	$ChinaChopperASPX
}