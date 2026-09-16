rule TTP_XOR_QUAD_CurrentVersionRun_7dfe {
  strings:
    $key_7dfe = { 2e 91 [2] 0a 9f [2] 21 b3 [2] 0f 91 [2] 1b 8a [2] 14 90 [2] 0a 8d [2] 08 8c [2] 13 8a [2] 0f 8d [2] 13 a2 }

  condition:
    any of them
}