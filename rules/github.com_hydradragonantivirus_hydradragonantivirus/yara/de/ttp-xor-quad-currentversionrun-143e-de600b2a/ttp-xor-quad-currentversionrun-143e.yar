rule TTP_XOR_QUAD_CurrentVersionRun_143e {
  strings:
    $key_143e = { 47 51 [2] 63 5f [2] 48 73 [2] 66 51 [2] 72 4a [2] 7d 50 [2] 63 4d [2] 61 4c [2] 7a 4a [2] 66 4d [2] 7a 62 }

  condition:
    any of them
}