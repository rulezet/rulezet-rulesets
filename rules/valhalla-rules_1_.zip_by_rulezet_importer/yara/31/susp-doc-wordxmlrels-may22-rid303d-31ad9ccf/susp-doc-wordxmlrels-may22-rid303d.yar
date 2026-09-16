rule SUSP_Doc_WordXMLRels_May22_RID303D : CVE_2022_30190 DEMO SUSP {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      date = "2022-05-30 12:31:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-06-20"
      tags = "CVE_2022_30190, DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii
      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
      $x3 = "%2E%68%74%6D%6C%21" ascii
      $x4 = "%2E%68%74%6D%21" ascii
   condition: 
      filesize < 50KB and all of ( $a* ) and 1 of ( $x* )
}