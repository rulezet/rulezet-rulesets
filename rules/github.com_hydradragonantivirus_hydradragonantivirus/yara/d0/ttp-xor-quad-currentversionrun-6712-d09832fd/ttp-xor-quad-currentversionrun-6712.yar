rule TTP_XOR_QUAD_CurrentVersionRun_6712 {
  strings:
    $key_6712 = { 34 7d [2] 10 73 [2] 3b 5f [2] 15 7d [2] 01 66 [2] 0e 7c [2] 10 61 [2] 12 60 [2] 09 66 [2] 15 61 [2] 09 4e }

  condition:
    any of them
}