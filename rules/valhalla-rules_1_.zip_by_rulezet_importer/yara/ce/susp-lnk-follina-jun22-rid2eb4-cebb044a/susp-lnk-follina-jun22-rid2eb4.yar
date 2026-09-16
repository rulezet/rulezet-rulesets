rule SUSP_LNK_Follina_Jun22_RID2EB4 : CVE_2022_30190 DEMO FILE SUSP T1210 T1547_009 {
   meta:
      description = "Detects LNK files with suspicious Follina / CVE-2022-30190 strings"
      author = "Paul Hager"
      reference = "https://twitter.com/gossithedog/status/1531650897905950727"
      date = "2022-06-02 11:25:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_30190, DEMO, FILE, SUSP, T1210, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt:" ascii wide
      $sb = "IT_BrowseForFile=" ascii wide
   condition: 
      filesize < 5KB and uint16 ( 0 ) == 0x004c and uint32 ( 4 ) == 0x00021401 and 1 of ( $sa* ) and $sb
}