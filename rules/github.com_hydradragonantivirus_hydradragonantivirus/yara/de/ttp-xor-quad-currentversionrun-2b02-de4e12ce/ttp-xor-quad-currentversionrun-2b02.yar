rule TTP_XOR_QUAD_CurrentVersionRun_2b02 {
  strings:
    $key_2b02 = { 78 6d [2] 5c 63 [2] 77 4f [2] 59 6d [2] 4d 76 [2] 42 6c [2] 5c 71 [2] 5e 70 [2] 45 76 [2] 59 71 [2] 45 5e }

  condition:
    any of them
}