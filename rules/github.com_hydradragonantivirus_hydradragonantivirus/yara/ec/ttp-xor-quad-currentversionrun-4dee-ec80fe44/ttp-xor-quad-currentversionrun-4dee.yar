rule TTP_XOR_QUAD_CurrentVersionRun_4dee {
  strings:
    $key_4dee = { 1e 81 [2] 3a 8f [2] 11 a3 [2] 3f 81 [2] 2b 9a [2] 24 80 [2] 3a 9d [2] 38 9c [2] 23 9a [2] 3f 9d [2] 23 b2 }

  condition:
    any of them
}