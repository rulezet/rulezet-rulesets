rule TTP_XOR_QUAD_CurrentVersionRun_49fe {
  strings:
    $key_49fe = { 1a 91 [2] 3e 9f [2] 15 b3 [2] 3b 91 [2] 2f 8a [2] 20 90 [2] 3e 8d [2] 3c 8c [2] 27 8a [2] 3b 8d [2] 27 a2 }

  condition:
    any of them
}