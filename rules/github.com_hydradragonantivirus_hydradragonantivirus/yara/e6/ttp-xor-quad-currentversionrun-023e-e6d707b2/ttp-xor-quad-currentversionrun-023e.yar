rule TTP_XOR_QUAD_CurrentVersionRun_023e {
  strings:
    $key_023e = { 51 51 [2] 75 5f [2] 5e 73 [2] 70 51 [2] 64 4a [2] 6b 50 [2] 75 4d [2] 77 4c [2] 6c 4a [2] 70 4d [2] 6c 62 }

  condition:
    any of them
}