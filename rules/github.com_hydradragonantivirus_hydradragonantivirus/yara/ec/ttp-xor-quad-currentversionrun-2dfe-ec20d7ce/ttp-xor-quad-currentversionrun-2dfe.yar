rule TTP_XOR_QUAD_CurrentVersionRun_2dfe {
  strings:
    $key_2dfe = { 7e 91 [2] 5a 9f [2] 71 b3 [2] 5f 91 [2] 4b 8a [2] 44 90 [2] 5a 8d [2] 58 8c [2] 43 8a [2] 5f 8d [2] 43 a2 }

  condition:
    any of them
}