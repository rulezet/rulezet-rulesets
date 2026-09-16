rule TTP_XOR_QUAD_CurrentVersionRun_2912 {
  strings:
    $key_2912 = { 7a 7d [2] 5e 73 [2] 75 5f [2] 5b 7d [2] 4f 66 [2] 40 7c [2] 5e 61 [2] 5c 60 [2] 47 66 [2] 5b 61 [2] 47 4e }

  condition:
    any of them
}