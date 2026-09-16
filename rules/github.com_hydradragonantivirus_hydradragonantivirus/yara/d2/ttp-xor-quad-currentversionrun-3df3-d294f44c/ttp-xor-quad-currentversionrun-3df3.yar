rule TTP_XOR_QUAD_CurrentVersionRun_3df3 {
  strings:
    $key_3df3 = { 6e 9c [2] 4a 92 [2] 61 be [2] 4f 9c [2] 5b 87 [2] 54 9d [2] 4a 80 [2] 48 81 [2] 53 87 [2] 4f 80 [2] 53 af }

  condition:
    any of them
}