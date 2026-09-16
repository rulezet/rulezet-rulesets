rule TTP_XOR_QUAD_CurrentVersionRun_3c38 {
  strings:
    $key_3c38 = { 6f 57 [2] 4b 59 [2] 60 75 [2] 4e 57 [2] 5a 4c [2] 55 56 [2] 4b 4b [2] 49 4a [2] 52 4c [2] 4e 4b [2] 52 64 }

  condition:
    any of them
}