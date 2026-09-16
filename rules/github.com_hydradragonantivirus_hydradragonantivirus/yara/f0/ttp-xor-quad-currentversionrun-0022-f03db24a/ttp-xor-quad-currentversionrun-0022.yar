rule TTP_XOR_QUAD_CurrentVersionRun_0022 {
  strings:
    $key_0022 = { 53 4d [2] 77 43 [2] 5c 6f [2] 72 4d [2] 66 56 [2] 69 4c [2] 77 51 [2] 75 50 [2] 6e 56 [2] 72 51 [2] 6e 7e }

  condition:
    any of them
}