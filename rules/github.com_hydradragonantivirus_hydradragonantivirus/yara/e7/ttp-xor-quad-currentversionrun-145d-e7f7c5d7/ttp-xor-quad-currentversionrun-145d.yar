rule TTP_XOR_QUAD_CurrentVersionRun_145d {
  strings:
    $key_145d = { 47 32 [2] 63 3c [2] 48 10 [2] 66 32 [2] 72 29 [2] 7d 33 [2] 63 2e [2] 61 2f [2] 7a 29 [2] 66 2e [2] 7a 01 }

  condition:
    any of them
}