rule TTP_XOR_QUAD_CurrentVersionRun_29f7 {
  strings:
    $key_29f7 = { 7a 98 [2] 5e 96 [2] 75 ba [2] 5b 98 [2] 4f 83 [2] 40 99 [2] 5e 84 [2] 5c 85 [2] 47 83 [2] 5b 84 [2] 47 ab }

  condition:
    any of them
}