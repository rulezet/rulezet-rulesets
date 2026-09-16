rule TTP_XOR_QUAD_CurrentVersionRun_6d22 {
  strings:
    $key_6d22 = { 3e 4d [2] 1a 43 [2] 31 6f [2] 1f 4d [2] 0b 56 [2] 04 4c [2] 1a 51 [2] 18 50 [2] 03 56 [2] 1f 51 [2] 03 7e }

  condition:
    any of them
}