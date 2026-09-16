rule TTP_XOR_QUAD_CurrentVersionRun_655d {
  strings:
    $key_655d = { 36 32 [2] 12 3c [2] 39 10 [2] 17 32 [2] 03 29 [2] 0c 33 [2] 12 2e [2] 10 2f [2] 0b 29 [2] 17 2e [2] 0b 01 }

  condition:
    any of them
}