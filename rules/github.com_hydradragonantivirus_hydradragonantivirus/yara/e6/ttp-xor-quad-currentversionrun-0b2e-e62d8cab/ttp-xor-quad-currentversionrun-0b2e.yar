rule TTP_XOR_QUAD_CurrentVersionRun_0b2e {
  strings:
    $key_0b2e = { 58 41 [2] 7c 4f [2] 57 63 [2] 79 41 [2] 6d 5a [2] 62 40 [2] 7c 5d [2] 7e 5c [2] 65 5a [2] 79 5d [2] 65 72 }

  condition:
    any of them
}