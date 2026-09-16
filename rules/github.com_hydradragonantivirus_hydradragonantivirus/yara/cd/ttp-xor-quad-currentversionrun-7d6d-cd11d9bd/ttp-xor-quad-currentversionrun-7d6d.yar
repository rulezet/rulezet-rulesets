rule TTP_XOR_QUAD_CurrentVersionRun_7d6d {
  strings:
    $key_7d6d = { 2e 02 [2] 0a 0c [2] 21 20 [2] 0f 02 [2] 1b 19 [2] 14 03 [2] 0a 1e [2] 08 1f [2] 13 19 [2] 0f 1e [2] 13 31 }

  condition:
    any of them
}