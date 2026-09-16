rule TTP_XOR_QUAD_CurrentVersionRun_286c {
  strings:
    $key_286c = { 7b 03 [2] 5f 0d [2] 74 21 [2] 5a 03 [2] 4e 18 [2] 41 02 [2] 5f 1f [2] 5d 1e [2] 46 18 [2] 5a 1f [2] 46 30 }

  condition:
    any of them
}