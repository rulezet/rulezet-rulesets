rule TTP_XOR_QUAD_CurrentVersionRun_4dfe {
  strings:
    $key_4dfe = { 1e 91 [2] 3a 9f [2] 11 b3 [2] 3f 91 [2] 2b 8a [2] 24 90 [2] 3a 8d [2] 38 8c [2] 23 8a [2] 3f 8d [2] 23 a2 }

  condition:
    any of them
}