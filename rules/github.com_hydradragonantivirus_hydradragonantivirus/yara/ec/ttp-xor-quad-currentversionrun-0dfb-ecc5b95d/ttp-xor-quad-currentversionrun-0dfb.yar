rule TTP_XOR_QUAD_CurrentVersionRun_0dfb {
  strings:
    $key_0dfb = { 5e 94 [2] 7a 9a [2] 51 b6 [2] 7f 94 [2] 6b 8f [2] 64 95 [2] 7a 88 [2] 78 89 [2] 63 8f [2] 7f 88 [2] 63 a7 }

  condition:
    any of them
}