rule TTP_XOR_QUAD_CurrentVersionRun_067a {
  strings:
    $key_067a = { 55 15 [2] 71 1b [2] 5a 37 [2] 74 15 [2] 60 0e [2] 6f 14 [2] 71 09 [2] 73 08 [2] 68 0e [2] 74 09 [2] 68 26 }

  condition:
    any of them
}