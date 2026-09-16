rule TTP_XOR_QUAD_CurrentVersionRun_2112 {
  strings:
    $key_2112 = { 72 7d [2] 56 73 [2] 7d 5f [2] 53 7d [2] 47 66 [2] 48 7c [2] 56 61 [2] 54 60 [2] 4f 66 [2] 53 61 [2] 4f 4e }

  condition:
    any of them
}