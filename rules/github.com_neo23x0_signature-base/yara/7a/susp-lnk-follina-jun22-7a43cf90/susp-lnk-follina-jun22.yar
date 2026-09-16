rule SUSP_LNK_Follina_Jun22 {
   meta:
      description = "Detects LNK files with suspicious Follina/CVE-2022-30190 strings"
      author = "Paul Hager"
      date = "2022-06-02"
      reference = "https://twitter.com/gossithedog/status/1531650897905950727"
      score = 75
      id = "d331d584-2ab3-5275-b435-6129c7291417"
   strings:
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt:" ascii wide

      $sb = "IT_BrowseForFile=" ascii wide
   condition:
      filesize < 5KB and
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and
      1 of ($sa*) and $sb
}