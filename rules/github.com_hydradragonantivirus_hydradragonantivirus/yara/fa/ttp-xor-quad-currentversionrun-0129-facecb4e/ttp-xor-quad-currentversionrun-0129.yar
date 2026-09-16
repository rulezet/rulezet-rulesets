rule TTP_XOR_QUAD_CurrentVersionRun_0129 {
  strings:
    $key_0129 = { 52 46 [2] 76 48 [2] 5d 64 [2] 73 46 [2] 67 5d [2] 68 47 [2] 76 5a [2] 74 5b [2] 6f 5d [2] 73 5a [2] 6f 75 }

  condition:
    any of them
}