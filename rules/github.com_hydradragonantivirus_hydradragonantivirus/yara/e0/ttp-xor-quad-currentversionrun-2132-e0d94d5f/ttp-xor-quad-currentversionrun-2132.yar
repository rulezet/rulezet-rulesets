rule TTP_XOR_QUAD_CurrentVersionRun_2132 {
  strings:
    $key_2132 = { 72 5d [2] 56 53 [2] 7d 7f [2] 53 5d [2] 47 46 [2] 48 5c [2] 56 41 [2] 54 40 [2] 4f 46 [2] 53 41 [2] 4f 6e }

  condition:
    any of them
}