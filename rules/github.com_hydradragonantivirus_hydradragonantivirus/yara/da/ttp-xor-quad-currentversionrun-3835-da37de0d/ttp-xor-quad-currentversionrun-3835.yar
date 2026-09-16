rule TTP_XOR_QUAD_CurrentVersionRun_3835 {
  strings:
    $key_3835 = { 6b 5a [2] 4f 54 [2] 64 78 [2] 4a 5a [2] 5e 41 [2] 51 5b [2] 4f 46 [2] 4d 47 [2] 56 41 [2] 4a 46 [2] 56 69 }

  condition:
    any of them
}