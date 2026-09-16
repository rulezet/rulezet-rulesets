rule TTP_XOR_QUAD_CurrentVersionRun_3524 {
  strings:
    $key_3524 = { 66 4b [2] 42 45 [2] 69 69 [2] 47 4b [2] 53 50 [2] 5c 4a [2] 42 57 [2] 40 56 [2] 5b 50 [2] 47 57 [2] 5b 78 }

  condition:
    any of them
}