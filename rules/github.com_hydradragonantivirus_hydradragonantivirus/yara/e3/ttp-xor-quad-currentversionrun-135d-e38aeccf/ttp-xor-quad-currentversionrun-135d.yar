rule TTP_XOR_QUAD_CurrentVersionRun_135d {
  strings:
    $key_135d = { 40 32 [2] 64 3c [2] 4f 10 [2] 61 32 [2] 75 29 [2] 7a 33 [2] 64 2e [2] 66 2f [2] 7d 29 [2] 61 2e [2] 7d 01 }

  condition:
    any of them
}