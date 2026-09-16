rule TTP_XOR_QUAD_CurrentVersionRun_65fe {
  strings:
    $key_65fe = { 36 91 [2] 12 9f [2] 39 b3 [2] 17 91 [2] 03 8a [2] 0c 90 [2] 12 8d [2] 10 8c [2] 0b 8a [2] 17 8d [2] 0b a2 }

  condition:
    any of them
}