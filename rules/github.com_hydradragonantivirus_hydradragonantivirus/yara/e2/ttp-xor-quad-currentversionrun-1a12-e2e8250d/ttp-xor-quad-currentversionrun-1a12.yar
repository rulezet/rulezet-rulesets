rule TTP_XOR_QUAD_CurrentVersionRun_1a12 {
  strings:
    $key_1a12 = { 49 7d [2] 6d 73 [2] 46 5f [2] 68 7d [2] 7c 66 [2] 73 7c [2] 6d 61 [2] 6f 60 [2] 74 66 [2] 68 61 [2] 74 4e }

  condition:
    any of them
}