rule TTP_XOR_QUAD_CurrentVersionRun_7cfe {
  strings:
    $key_7cfe = { 2f 91 [2] 0b 9f [2] 20 b3 [2] 0e 91 [2] 1a 8a [2] 15 90 [2] 0b 8d [2] 09 8c [2] 12 8a [2] 0e 8d [2] 12 a2 }

  condition:
    any of them
}