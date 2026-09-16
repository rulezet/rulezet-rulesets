rule WEBSHELL_ASP_Embedded_Mar21_1 {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-05"
      score = 85
      id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form["
      $s3 = ".Write(Request.Form["
   condition:
      filesize < 100KB and all of them
}