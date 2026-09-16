rule TTP_XOR_QUAD_CurrentVersionRun_79fe {
  strings:
    $key_79fe = { 2a 91 [2] 0e 9f [2] 25 b3 [2] 0b 91 [2] 1f 8a [2] 10 90 [2] 0e 8d [2] 0c 8c [2] 17 8a [2] 0b 8d [2] 17 a2 }

  condition:
    any of them
}