rule TTP_XOR_QUAD_CurrentVersionRun_e234 {
  strings:
    $key_e234 = { b1 5b [2] 95 55 [2] be 79 [2] 90 5b [2] 84 40 [2] 8b 5a [2] 95 47 [2] 97 46 [2] 8c 40 [2] 90 47 [2] 8c 68 }

  condition:
    any of them
}