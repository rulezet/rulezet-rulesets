rule TTP_XOR_QUAD_CurrentVersionRun_3212 {
  strings:
    $key_3212 = { 61 7d [2] 45 73 [2] 6e 5f [2] 40 7d [2] 54 66 [2] 5b 7c [2] 45 61 [2] 47 60 [2] 5c 66 [2] 40 61 [2] 5c 4e }

  condition:
    any of them
}