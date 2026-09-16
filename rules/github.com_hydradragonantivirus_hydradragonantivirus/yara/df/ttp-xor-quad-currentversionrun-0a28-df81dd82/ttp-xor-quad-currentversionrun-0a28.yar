rule TTP_XOR_QUAD_CurrentVersionRun_0a28 {
  strings:
    $key_0a28 = { 59 47 [2] 7d 49 [2] 56 65 [2] 78 47 [2] 6c 5c [2] 63 46 [2] 7d 5b [2] 7f 5a [2] 64 5c [2] 78 5b [2] 64 74 }

  condition:
    any of them
}