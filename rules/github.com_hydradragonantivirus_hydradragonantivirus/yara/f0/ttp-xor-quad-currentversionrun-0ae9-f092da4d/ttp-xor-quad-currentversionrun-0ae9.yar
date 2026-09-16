rule TTP_XOR_QUAD_CurrentVersionRun_0ae9 {
  strings:
    $key_0ae9 = { 59 86 [2] 7d 88 [2] 56 a4 [2] 78 86 [2] 6c 9d [2] 63 87 [2] 7d 9a [2] 7f 9b [2] 64 9d [2] 78 9a [2] 64 b5 }

  condition:
    any of them
}