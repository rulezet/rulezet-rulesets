rule TTP_XOR_QUAD_CurrentVersionRun_6256 {
  strings:
    $key_6256 = { 31 39 [2] 15 37 [2] 3e 1b [2] 10 39 [2] 04 22 [2] 0b 38 [2] 15 25 [2] 17 24 [2] 0c 22 [2] 10 25 [2] 0c 0a }

  condition:
    any of them
}