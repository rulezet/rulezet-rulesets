rule TTP_XOR_QUAD_CurrentVersionRun_0f7d {
  strings:
    $key_0f7d = { 5c 12 [2] 78 1c [2] 53 30 [2] 7d 12 [2] 69 09 [2] 66 13 [2] 78 0e [2] 7a 0f [2] 61 09 [2] 7d 0e [2] 61 21 }

  condition:
    any of them
}