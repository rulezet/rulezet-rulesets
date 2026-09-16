rule TTP_XOR_QUAD_CurrentVersionRun_5742 {
  strings:
    $key_5742 = { 04 2d [2] 20 23 [2] 0b 0f [2] 25 2d [2] 31 36 [2] 3e 2c [2] 20 31 [2] 22 30 [2] 39 36 [2] 25 31 [2] 39 1e }

  condition:
    any of them
}