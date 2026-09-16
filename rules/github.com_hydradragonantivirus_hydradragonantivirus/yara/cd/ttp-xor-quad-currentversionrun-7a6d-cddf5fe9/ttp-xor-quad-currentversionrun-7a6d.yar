rule TTP_XOR_QUAD_CurrentVersionRun_7a6d {
  strings:
    $key_7a6d = { 29 02 [2] 0d 0c [2] 26 20 [2] 08 02 [2] 1c 19 [2] 13 03 [2] 0d 1e [2] 0f 1f [2] 14 19 [2] 08 1e [2] 14 31 }

  condition:
    any of them
}