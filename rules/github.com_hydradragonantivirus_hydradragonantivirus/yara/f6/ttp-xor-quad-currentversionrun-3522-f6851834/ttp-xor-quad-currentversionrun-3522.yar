rule TTP_XOR_QUAD_CurrentVersionRun_3522 {
  strings:
    $key_3522 = { 66 4d [2] 42 43 [2] 69 6f [2] 47 4d [2] 53 56 [2] 5c 4c [2] 42 51 [2] 40 50 [2] 5b 56 [2] 47 51 [2] 5b 7e }

  condition:
    any of them
}