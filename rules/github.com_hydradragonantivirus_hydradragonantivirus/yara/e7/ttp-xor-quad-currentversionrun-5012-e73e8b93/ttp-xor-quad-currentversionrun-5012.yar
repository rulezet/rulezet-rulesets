rule TTP_XOR_QUAD_CurrentVersionRun_5012 {
  strings:
    $key_5012 = { 03 7d [2] 27 73 [2] 0c 5f [2] 22 7d [2] 36 66 [2] 39 7c [2] 27 61 [2] 25 60 [2] 3e 66 [2] 22 61 [2] 3e 4e }

  condition:
    any of them
}