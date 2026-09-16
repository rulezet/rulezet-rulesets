rule TTP_XOR_QUAD_CurrentVersionRun_4632 {
  strings:
    $key_4632 = { 15 5d [2] 31 53 [2] 1a 7f [2] 34 5d [2] 20 46 [2] 2f 5c [2] 31 41 [2] 33 40 [2] 28 46 [2] 34 41 [2] 28 6e }

  condition:
    any of them
}