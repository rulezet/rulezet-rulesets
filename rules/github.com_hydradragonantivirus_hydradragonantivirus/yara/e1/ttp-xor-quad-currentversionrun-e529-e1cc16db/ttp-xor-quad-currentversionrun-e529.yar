rule TTP_XOR_QUAD_CurrentVersionRun_e529 {
  strings:
    $key_e529 = { b6 46 [2] 92 48 [2] b9 64 [2] 97 46 [2] 83 5d [2] 8c 47 [2] 92 5a [2] 90 5b [2] 8b 5d [2] 97 5a [2] 8b 75 }

  condition:
    any of them
}