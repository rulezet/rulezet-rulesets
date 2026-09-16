rule TTP_XOR_QUAD_CurrentVersionRun_3a6c {
  strings:
    $key_3a6c = { 69 03 [2] 4d 0d [2] 66 21 [2] 48 03 [2] 5c 18 [2] 53 02 [2] 4d 1f [2] 4f 1e [2] 54 18 [2] 48 1f [2] 54 30 }

  condition:
    any of them
}