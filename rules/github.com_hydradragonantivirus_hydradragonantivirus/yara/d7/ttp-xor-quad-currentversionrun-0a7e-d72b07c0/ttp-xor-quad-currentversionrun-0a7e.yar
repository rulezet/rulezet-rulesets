rule TTP_XOR_QUAD_CurrentVersionRun_0a7e {
  strings:
    $key_0a7e = { 59 11 [2] 7d 1f [2] 56 33 [2] 78 11 [2] 6c 0a [2] 63 10 [2] 7d 0d [2] 7f 0c [2] 64 0a [2] 78 0d [2] 64 22 }

  condition:
    any of them
}