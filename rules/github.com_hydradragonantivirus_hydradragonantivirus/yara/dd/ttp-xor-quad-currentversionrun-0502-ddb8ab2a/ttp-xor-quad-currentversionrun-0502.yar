rule TTP_XOR_QUAD_CurrentVersionRun_0502 {
  strings:
    $key_0502 = { 56 6d [2] 72 63 [2] 59 4f [2] 77 6d [2] 63 76 [2] 6c 6c [2] 72 71 [2] 70 70 [2] 6b 76 [2] 77 71 [2] 6b 5e }

  condition:
    any of them
}