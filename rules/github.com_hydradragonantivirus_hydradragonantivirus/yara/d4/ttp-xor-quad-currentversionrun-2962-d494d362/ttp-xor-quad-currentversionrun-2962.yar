rule TTP_XOR_QUAD_CurrentVersionRun_2962 {
  strings:
    $key_2962 = { 7a 0d [2] 5e 03 [2] 75 2f [2] 5b 0d [2] 4f 16 [2] 40 0c [2] 5e 11 [2] 5c 10 [2] 47 16 [2] 5b 11 [2] 47 3e }

  condition:
    any of them
}