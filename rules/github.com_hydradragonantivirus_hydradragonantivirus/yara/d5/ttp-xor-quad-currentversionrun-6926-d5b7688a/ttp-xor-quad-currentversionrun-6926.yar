rule TTP_XOR_QUAD_CurrentVersionRun_6926 {
  strings:
    $key_6926 = { 3a 49 [2] 1e 47 [2] 35 6b [2] 1b 49 [2] 0f 52 [2] 00 48 [2] 1e 55 [2] 1c 54 [2] 07 52 [2] 1b 55 [2] 07 7a }

  condition:
    any of them
}