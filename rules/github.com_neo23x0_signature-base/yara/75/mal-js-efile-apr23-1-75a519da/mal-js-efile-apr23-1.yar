rule MAL_JS_EFile_Apr23_1 {
   meta:
      description = "Detects JavaScript malware used in eFile compromise"
      author = "Florian Roth"
      score = 75
      reference = "https://twitter.com/Ax_Sharma/status/1643178696084271104/photo/1"
      date = "2023-04-06"
      id = "ba7a8b2c-789c-5bc5-be53-f2b92c7039e1"
   strings:
      $s1 = "let payload_chrome = "
      $s2 = "else if (agent.indexOf(\"firefox"
   condition:
      all of them
}