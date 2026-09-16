rule TTP_XOR_QUAD_CurrentVersionRun_2338 {
  strings:
    $key_2338 = { 70 57 [2] 54 59 [2] 7f 75 [2] 51 57 [2] 45 4c [2] 4a 56 [2] 54 4b [2] 56 4a [2] 4d 4c [2] 51 4b [2] 4d 64 }

  condition:
    any of them
}