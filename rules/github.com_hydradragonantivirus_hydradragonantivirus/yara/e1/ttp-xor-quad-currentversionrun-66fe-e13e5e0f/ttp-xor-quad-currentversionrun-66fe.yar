rule TTP_XOR_QUAD_CurrentVersionRun_66fe {
  strings:
    $key_66fe = { 35 91 [2] 11 9f [2] 3a b3 [2] 14 91 [2] 00 8a [2] 0f 90 [2] 11 8d [2] 13 8c [2] 08 8a [2] 14 8d [2] 08 a2 }

  condition:
    any of them
}