rule TTP_XOR_QUAD_CurrentVersionRun_311c {
  strings:
    $key_311c = { 62 73 [2] 46 7d [2] 6d 51 [2] 43 73 [2] 57 68 [2] 58 72 [2] 46 6f [2] 44 6e [2] 5f 68 [2] 43 6f [2] 5f 40 }

  condition:
    any of them
}