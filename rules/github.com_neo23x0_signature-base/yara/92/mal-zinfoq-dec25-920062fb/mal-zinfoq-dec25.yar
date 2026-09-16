rule MAL_ZinFoq_Dec25 {
   meta:
      description = "Detects ZinFoq Go-based Linux post-exploitation implant (interactive shell + file ops/exfil) seen in React2Shell intrusions"
      author = "RussianPanda"
      date = "2025-12-08"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "0f0f9c339fcc267ec3d560c7168c56f607232cbeb158cb02a0818720a54e72ce"
   strings:
      $s1 = "_FlAg_UuId;;;;;;"
      $s2 = "interactive_shell"
      $s3 = "explorer_download"
   condition:
      uint32(0) == 0x464c457f and all of them
}