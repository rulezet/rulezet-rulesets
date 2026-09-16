rule TTP_XOR_QUAD_CurrentVersionRun_012a {
  strings:
    $key_012a = { 52 45 [2] 76 4b [2] 5d 67 [2] 73 45 [2] 67 5e [2] 68 44 [2] 76 59 [2] 74 58 [2] 6f 5e [2] 73 59 [2] 6f 76 }

  condition:
    any of them
}