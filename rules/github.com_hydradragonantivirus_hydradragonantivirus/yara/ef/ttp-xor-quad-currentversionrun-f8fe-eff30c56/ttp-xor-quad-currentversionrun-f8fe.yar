rule TTP_XOR_QUAD_CurrentVersionRun_f8fe {
  strings:
    $key_f8fe = { ab 91 [2] 8f 9f [2] a4 b3 [2] 8a 91 [2] 9e 8a [2] 91 90 [2] 8f 8d [2] 8d 8c [2] 96 8a [2] 8a 8d [2] 96 a2 }

  condition:
    any of them
}