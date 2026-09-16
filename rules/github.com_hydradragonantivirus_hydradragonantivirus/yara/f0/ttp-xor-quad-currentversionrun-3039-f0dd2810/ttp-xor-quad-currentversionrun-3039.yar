rule TTP_XOR_QUAD_CurrentVersionRun_3039 {
  strings:
    $key_3039 = { 63 56 [2] 47 58 [2] 6c 74 [2] 42 56 [2] 56 4d [2] 59 57 [2] 47 4a [2] 45 4b [2] 5e 4d [2] 42 4a [2] 5e 65 }

  condition:
    any of them
}