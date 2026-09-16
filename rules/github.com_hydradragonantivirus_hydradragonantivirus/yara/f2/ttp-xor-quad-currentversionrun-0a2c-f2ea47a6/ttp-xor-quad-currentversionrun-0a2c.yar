rule TTP_XOR_QUAD_CurrentVersionRun_0a2c {
  strings:
    $key_0a2c = { 59 43 [2] 7d 4d [2] 56 61 [2] 78 43 [2] 6c 58 [2] 63 42 [2] 7d 5f [2] 7f 5e [2] 64 58 [2] 78 5f [2] 64 70 }

  condition:
    any of them
}