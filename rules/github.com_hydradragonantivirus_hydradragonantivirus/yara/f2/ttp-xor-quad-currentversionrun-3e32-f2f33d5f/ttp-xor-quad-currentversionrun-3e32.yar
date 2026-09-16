rule TTP_XOR_QUAD_CurrentVersionRun_3e32 {
  strings:
    $key_3e32 = { 6d 5d [2] 49 53 [2] 62 7f [2] 4c 5d [2] 58 46 [2] 57 5c [2] 49 41 [2] 4b 40 [2] 50 46 [2] 4c 41 [2] 50 6e }

  condition:
    any of them
}