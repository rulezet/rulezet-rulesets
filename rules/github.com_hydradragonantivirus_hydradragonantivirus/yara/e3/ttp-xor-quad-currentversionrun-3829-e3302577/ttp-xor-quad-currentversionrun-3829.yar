rule TTP_XOR_QUAD_CurrentVersionRun_3829 {
  strings:
    $key_3829 = { 6b 46 [2] 4f 48 [2] 64 64 [2] 4a 46 [2] 5e 5d [2] 51 47 [2] 4f 5a [2] 4d 5b [2] 56 5d [2] 4a 5a [2] 56 75 }

  condition:
    any of them
}