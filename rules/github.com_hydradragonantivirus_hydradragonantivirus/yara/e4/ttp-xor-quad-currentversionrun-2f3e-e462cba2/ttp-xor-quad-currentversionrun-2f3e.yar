rule TTP_XOR_QUAD_CurrentVersionRun_2f3e {
  strings:
    $key_2f3e = { 7c 51 [2] 58 5f [2] 73 73 [2] 5d 51 [2] 49 4a [2] 46 50 [2] 58 4d [2] 5a 4c [2] 41 4a [2] 5d 4d [2] 41 62 }

  condition:
    any of them
}