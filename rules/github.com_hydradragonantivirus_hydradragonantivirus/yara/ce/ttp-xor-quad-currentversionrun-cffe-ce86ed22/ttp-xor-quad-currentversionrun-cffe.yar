rule TTP_XOR_QUAD_CurrentVersionRun_cffe {
  strings:
    $key_cffe = { 9c 91 [2] b8 9f [2] 93 b3 [2] bd 91 [2] a9 8a [2] a6 90 [2] b8 8d [2] ba 8c [2] a1 8a [2] bd 8d [2] a1 a2 }

  condition:
    any of them
}