rule SUSP_LNK_File_PathTraversal_RID311F : DEMO FILE SUSP T1210 T1547_009 {
   meta:
      description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16 13:09:01"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP, T1210, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "..\\..\\..\\..\\..\\" 
   condition: 
      uint16 ( 0 ) == 0x004c and uint32 ( 4 ) == 0x00021401 and ( filesize < 1KB and all of them )
}