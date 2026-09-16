rule TTP_XOR_QUAD_CurrentVersionRun_0822 {
  strings:
    $key_0822 = { 5b 4d [2] 7f 43 [2] 54 6f [2] 7a 4d [2] 6e 56 [2] 61 4c [2] 7f 51 [2] 7d 50 [2] 66 56 [2] 7a 51 [2] 66 7e }

  condition:
    any of them
}