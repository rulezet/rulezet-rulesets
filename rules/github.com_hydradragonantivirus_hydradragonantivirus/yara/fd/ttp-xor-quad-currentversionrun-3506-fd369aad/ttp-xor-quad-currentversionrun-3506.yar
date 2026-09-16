rule TTP_XOR_QUAD_CurrentVersionRun_3506 {
  strings:
    $key_3506 = { 66 69 [2] 42 67 [2] 69 4b [2] 47 69 [2] 53 72 [2] 5c 68 [2] 42 75 [2] 40 74 [2] 5b 72 [2] 47 75 [2] 5b 5a }

  condition:
    any of them
}