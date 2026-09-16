rule TTP_XOR_QUAD_CurrentVersionRun_062a {
  strings:
    $key_062a = { 55 45 [2] 71 4b [2] 5a 67 [2] 74 45 [2] 60 5e [2] 6f 44 [2] 71 59 [2] 73 58 [2] 68 5e [2] 74 59 [2] 68 76 }

  condition:
    any of them
}