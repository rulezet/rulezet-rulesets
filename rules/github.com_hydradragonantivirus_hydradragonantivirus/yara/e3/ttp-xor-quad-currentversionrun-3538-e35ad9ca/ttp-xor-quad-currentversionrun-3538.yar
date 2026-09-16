rule TTP_XOR_QUAD_CurrentVersionRun_3538 {
  strings:
    $key_3538 = { 66 57 [2] 42 59 [2] 69 75 [2] 47 57 [2] 53 4c [2] 5c 56 [2] 42 4b [2] 40 4a [2] 5b 4c [2] 47 4b [2] 5b 64 }

  condition:
    any of them
}