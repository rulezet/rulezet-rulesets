rule TTP_XOR_QUAD_CurrentVersionRun_213e {
  strings:
    $key_213e = { 72 51 [2] 56 5f [2] 7d 73 [2] 53 51 [2] 47 4a [2] 48 50 [2] 56 4d [2] 54 4c [2] 4f 4a [2] 53 4d [2] 4f 62 }

  condition:
    any of them
}