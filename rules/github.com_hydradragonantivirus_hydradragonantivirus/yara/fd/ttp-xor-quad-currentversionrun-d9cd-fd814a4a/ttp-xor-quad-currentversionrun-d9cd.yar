rule TTP_XOR_QUAD_CurrentVersionRun_d9cd {
  strings:
    $key_d9cd = { 8a a2 [2] ae ac [2] 85 80 [2] ab a2 [2] bf b9 [2] b0 a3 [2] ae be [2] ac bf [2] b7 b9 [2] ab be [2] b7 91 }

  condition:
    any of them
}