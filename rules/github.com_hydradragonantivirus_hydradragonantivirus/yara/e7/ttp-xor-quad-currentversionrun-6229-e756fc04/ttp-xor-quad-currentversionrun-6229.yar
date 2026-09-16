rule TTP_XOR_QUAD_CurrentVersionRun_6229 {
  strings:
    $key_6229 = { 31 46 [2] 15 48 [2] 3e 64 [2] 10 46 [2] 04 5d [2] 0b 47 [2] 15 5a [2] 17 5b [2] 0c 5d [2] 10 5a [2] 0c 75 }

  condition:
    any of them
}