rule TTP_XOR_QUAD_CurrentVersionRun_3512 {
  strings:
    $key_3512 = { 66 7d [2] 42 73 [2] 69 5f [2] 47 7d [2] 53 66 [2] 5c 7c [2] 42 61 [2] 40 60 [2] 5b 66 [2] 47 61 [2] 5b 4e }

  condition:
    any of them
}