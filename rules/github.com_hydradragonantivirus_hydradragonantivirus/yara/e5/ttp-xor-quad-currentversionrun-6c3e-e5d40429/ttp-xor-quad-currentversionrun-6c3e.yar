rule TTP_XOR_QUAD_CurrentVersionRun_6c3e {
  strings:
    $key_6c3e = { 3f 51 [2] 1b 5f [2] 30 73 [2] 1e 51 [2] 0a 4a [2] 05 50 [2] 1b 4d [2] 19 4c [2] 02 4a [2] 1e 4d [2] 02 62 }

  condition:
    any of them
}