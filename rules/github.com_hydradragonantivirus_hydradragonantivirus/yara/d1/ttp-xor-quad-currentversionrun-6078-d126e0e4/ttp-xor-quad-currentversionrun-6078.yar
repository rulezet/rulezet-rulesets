rule TTP_XOR_QUAD_CurrentVersionRun_6078 {
  strings:
    $key_6078 = { 33 17 [2] 17 19 [2] 3c 35 [2] 12 17 [2] 06 0c [2] 09 16 [2] 17 0b [2] 15 0a [2] 0e 0c [2] 12 0b [2] 0e 24 }

  condition:
    any of them
}