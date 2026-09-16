rule TTP_XOR_QUAD_CurrentVersionRun_0506 {
  strings:
    $key_0506 = { 56 69 [2] 72 67 [2] 59 4b [2] 77 69 [2] 63 72 [2] 6c 68 [2] 72 75 [2] 70 74 [2] 6b 72 [2] 77 75 [2] 6b 5a }

  condition:
    any of them
}