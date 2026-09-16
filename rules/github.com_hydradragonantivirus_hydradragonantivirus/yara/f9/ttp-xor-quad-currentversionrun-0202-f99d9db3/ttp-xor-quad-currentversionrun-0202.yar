rule TTP_XOR_QUAD_CurrentVersionRun_0202 {
  strings:
    $key_0202 = { 51 6d [2] 75 63 [2] 5e 4f [2] 70 6d [2] 64 76 [2] 6b 6c [2] 75 71 [2] 77 70 [2] 6c 76 [2] 70 71 [2] 6c 5e }

  condition:
    any of them
}