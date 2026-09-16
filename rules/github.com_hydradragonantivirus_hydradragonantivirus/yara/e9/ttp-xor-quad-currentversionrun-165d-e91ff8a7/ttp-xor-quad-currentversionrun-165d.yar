rule TTP_XOR_QUAD_CurrentVersionRun_165d {
  strings:
    $key_165d = { 45 32 [2] 61 3c [2] 4a 10 [2] 64 32 [2] 70 29 [2] 7f 33 [2] 61 2e [2] 63 2f [2] 78 29 [2] 64 2e [2] 78 01 }

  condition:
    any of them
}