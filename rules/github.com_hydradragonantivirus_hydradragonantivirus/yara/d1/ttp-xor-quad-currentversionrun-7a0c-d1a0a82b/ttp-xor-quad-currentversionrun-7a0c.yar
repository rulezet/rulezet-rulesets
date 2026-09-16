rule TTP_XOR_QUAD_CurrentVersionRun_7a0c {
  strings:
    $key_7a0c = { 29 63 [2] 0d 6d [2] 26 41 [2] 08 63 [2] 1c 78 [2] 13 62 [2] 0d 7f [2] 0f 7e [2] 14 78 [2] 08 7f [2] 14 50 }

  condition:
    any of them
}