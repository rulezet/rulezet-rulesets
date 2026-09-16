rule TTP_XOR_QUAD_CurrentVersionRun_0d14 {
  strings:
    $key_0d14 = { 5e 7b [2] 7a 75 [2] 51 59 [2] 7f 7b [2] 6b 60 [2] 64 7a [2] 7a 67 [2] 78 66 [2] 63 60 [2] 7f 67 [2] 63 48 }

  condition:
    any of them
}