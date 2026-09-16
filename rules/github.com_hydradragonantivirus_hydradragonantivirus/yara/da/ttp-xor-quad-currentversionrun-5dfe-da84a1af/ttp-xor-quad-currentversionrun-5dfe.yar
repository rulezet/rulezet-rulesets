rule TTP_XOR_QUAD_CurrentVersionRun_5dfe {
  strings:
    $key_5dfe = { 0e 91 [2] 2a 9f [2] 01 b3 [2] 2f 91 [2] 3b 8a [2] 34 90 [2] 2a 8d [2] 28 8c [2] 33 8a [2] 2f 8d [2] 33 a2 }

  condition:
    any of them
}