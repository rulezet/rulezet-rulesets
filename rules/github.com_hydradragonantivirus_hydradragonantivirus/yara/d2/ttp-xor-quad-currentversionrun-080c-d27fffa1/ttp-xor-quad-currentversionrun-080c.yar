rule TTP_XOR_QUAD_CurrentVersionRun_080c {
  strings:
    $key_080c = { 5b 63 [2] 7f 6d [2] 54 41 [2] 7a 63 [2] 6e 78 [2] 61 62 [2] 7f 7f [2] 7d 7e [2] 66 78 [2] 7a 7f [2] 66 50 }

  condition:
    any of them
}