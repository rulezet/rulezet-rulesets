rule TTP_XOR_QUAD_CurrentVersionRun_e829 {
  strings:
    $key_e829 = { bb 46 [2] 9f 48 [2] b4 64 [2] 9a 46 [2] 8e 5d [2] 81 47 [2] 9f 5a [2] 9d 5b [2] 86 5d [2] 9a 5a [2] 86 75 }

  condition:
    any of them
}