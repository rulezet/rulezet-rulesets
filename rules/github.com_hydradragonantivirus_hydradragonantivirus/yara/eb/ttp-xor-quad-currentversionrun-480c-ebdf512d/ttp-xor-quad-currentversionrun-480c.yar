rule TTP_XOR_QUAD_CurrentVersionRun_480c {
  strings:
    $key_480c = { 1b 63 [2] 3f 6d [2] 14 41 [2] 3a 63 [2] 2e 78 [2] 21 62 [2] 3f 7f [2] 3d 7e [2] 26 78 [2] 3a 7f [2] 26 50 }

  condition:
    any of them
}