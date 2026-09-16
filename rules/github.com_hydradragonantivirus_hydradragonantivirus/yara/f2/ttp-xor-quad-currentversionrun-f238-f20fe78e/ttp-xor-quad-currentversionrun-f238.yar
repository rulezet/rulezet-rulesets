rule TTP_XOR_QUAD_CurrentVersionRun_f238 {
  strings:
    $key_f238 = { a1 57 [2] 85 59 [2] ae 75 [2] 80 57 [2] 94 4c [2] 9b 56 [2] 85 4b [2] 87 4a [2] 9c 4c [2] 80 4b [2] 9c 64 }

  condition:
    any of them
}