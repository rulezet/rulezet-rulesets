rule TTP_XOR_QUAD_CurrentVersionRun_186d {
  strings:
    $key_186d = { 4b 02 [2] 6f 0c [2] 44 20 [2] 6a 02 [2] 7e 19 [2] 71 03 [2] 6f 1e [2] 6d 1f [2] 76 19 [2] 6a 1e [2] 76 31 }

  condition:
    any of them
}