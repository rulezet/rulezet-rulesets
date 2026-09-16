rule TTP_XOR_QUAD_CurrentVersionRun_7812 {
  strings:
    $key_7812 = { 2b 7d [2] 0f 73 [2] 24 5f [2] 0a 7d [2] 1e 66 [2] 11 7c [2] 0f 61 [2] 0d 60 [2] 16 66 [2] 0a 61 [2] 16 4e }

  condition:
    any of them
}