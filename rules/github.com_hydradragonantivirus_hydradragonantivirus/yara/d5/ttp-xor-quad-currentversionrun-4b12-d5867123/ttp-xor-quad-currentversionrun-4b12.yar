rule TTP_XOR_QUAD_CurrentVersionRun_4b12 {
  strings:
    $key_4b12 = { 18 7d [2] 3c 73 [2] 17 5f [2] 39 7d [2] 2d 66 [2] 22 7c [2] 3c 61 [2] 3e 60 [2] 25 66 [2] 39 61 [2] 25 4e }

  condition:
    any of them
}