rule TTP_XOR_QUAD_CurrentVersionRun_0832 {
  strings:
    $key_0832 = { 5b 5d [2] 7f 53 [2] 54 7f [2] 7a 5d [2] 6e 46 [2] 61 5c [2] 7f 41 [2] 7d 40 [2] 66 46 [2] 7a 41 [2] 66 6e }

  condition:
    any of them
}