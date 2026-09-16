rule TTP_XOR_QUAD_CurrentVersionRun_390c {
  strings:
    $key_390c = { 6a 63 [2] 4e 6d [2] 65 41 [2] 4b 63 [2] 5f 78 [2] 50 62 [2] 4e 7f [2] 4c 7e [2] 57 78 [2] 4b 7f [2] 57 50 }

  condition:
    any of them
}