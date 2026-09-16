rule TTP_XOR_QUAD_CurrentVersionRun_0a29 {
  strings:
    $key_0a29 = { 59 46 [2] 7d 48 [2] 56 64 [2] 78 46 [2] 6c 5d [2] 63 47 [2] 7d 5a [2] 7f 5b [2] 64 5d [2] 78 5a [2] 64 75 }

  condition:
    any of them
}