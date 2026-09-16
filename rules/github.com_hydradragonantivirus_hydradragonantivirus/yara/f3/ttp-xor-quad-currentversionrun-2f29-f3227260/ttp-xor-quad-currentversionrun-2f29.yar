rule TTP_XOR_QUAD_CurrentVersionRun_2f29 {
  strings:
    $key_2f29 = { 7c 46 [2] 58 48 [2] 73 64 [2] 5d 46 [2] 49 5d [2] 46 47 [2] 58 5a [2] 5a 5b [2] 41 5d [2] 5d 5a [2] 41 75 }

  condition:
    any of them
}