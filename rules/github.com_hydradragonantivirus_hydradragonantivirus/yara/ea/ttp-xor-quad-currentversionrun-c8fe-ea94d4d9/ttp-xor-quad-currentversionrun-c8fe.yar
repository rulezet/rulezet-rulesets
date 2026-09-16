rule TTP_XOR_QUAD_CurrentVersionRun_c8fe {
  strings:
    $key_c8fe = { 9b 91 [2] bf 9f [2] 94 b3 [2] ba 91 [2] ae 8a [2] a1 90 [2] bf 8d [2] bd 8c [2] a6 8a [2] ba 8d [2] a6 a2 }

  condition:
    any of them
}