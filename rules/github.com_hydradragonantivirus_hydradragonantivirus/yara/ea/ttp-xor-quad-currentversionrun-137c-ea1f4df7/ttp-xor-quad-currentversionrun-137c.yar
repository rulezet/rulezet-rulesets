rule TTP_XOR_QUAD_CurrentVersionRun_137c {
  strings:
    $key_137c = { 40 13 [2] 64 1d [2] 4f 31 [2] 61 13 [2] 75 08 [2] 7a 12 [2] 64 0f [2] 66 0e [2] 7d 08 [2] 61 0f [2] 7d 20 }

  condition:
    any of them
}