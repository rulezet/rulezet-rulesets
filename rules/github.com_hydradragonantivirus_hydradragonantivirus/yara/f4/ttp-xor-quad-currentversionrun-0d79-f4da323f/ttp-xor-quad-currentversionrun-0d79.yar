rule TTP_XOR_QUAD_CurrentVersionRun_0d79 {
  strings:
    $key_0d79 = { 5e 16 [2] 7a 18 [2] 51 34 [2] 7f 16 [2] 6b 0d [2] 64 17 [2] 7a 0a [2] 78 0b [2] 63 0d [2] 7f 0a [2] 63 25 }

  condition:
    any of them
}