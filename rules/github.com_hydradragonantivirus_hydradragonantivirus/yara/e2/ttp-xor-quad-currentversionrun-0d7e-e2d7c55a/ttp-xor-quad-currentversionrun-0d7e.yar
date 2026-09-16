rule TTP_XOR_QUAD_CurrentVersionRun_0d7e {
  strings:
    $key_0d7e = { 5e 11 [2] 7a 1f [2] 51 33 [2] 7f 11 [2] 6b 0a [2] 64 10 [2] 7a 0d [2] 78 0c [2] 63 0a [2] 7f 0d [2] 63 22 }

  condition:
    any of them
}