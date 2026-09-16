rule TTP_XOR_QUAD_CurrentVersionRun_073e {
  strings:
    $key_073e = { 54 51 [2] 70 5f [2] 5b 73 [2] 75 51 [2] 61 4a [2] 6e 50 [2] 70 4d [2] 72 4c [2] 69 4a [2] 75 4d [2] 69 62 }

  condition:
    any of them
}