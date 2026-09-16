rule TTP_XOR_QUAD_CurrentVersionRun_787e {
  strings:
    $key_787e = { 2b 11 [2] 0f 1f [2] 24 33 [2] 0a 11 [2] 1e 0a [2] 11 10 [2] 0f 0d [2] 0d 0c [2] 16 0a [2] 0a 0d [2] 16 22 }

  condition:
    any of them
}