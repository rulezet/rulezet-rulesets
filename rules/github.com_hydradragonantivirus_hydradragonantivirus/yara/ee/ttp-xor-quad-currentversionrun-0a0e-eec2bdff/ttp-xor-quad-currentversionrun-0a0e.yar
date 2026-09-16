rule TTP_XOR_QUAD_CurrentVersionRun_0a0e {
  strings:
    $key_0a0e = { 59 61 [2] 7d 6f [2] 56 43 [2] 78 61 [2] 6c 7a [2] 63 60 [2] 7d 7d [2] 7f 7c [2] 64 7a [2] 78 7d [2] 64 52 }

  condition:
    any of them
}