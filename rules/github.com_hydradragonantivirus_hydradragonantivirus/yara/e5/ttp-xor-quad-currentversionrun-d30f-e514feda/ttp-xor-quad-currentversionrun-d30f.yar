rule TTP_XOR_QUAD_CurrentVersionRun_d30f {
  strings:
    $key_d30f = { 80 60 [2] a4 6e [2] 8f 42 [2] a1 60 [2] b5 7b [2] ba 61 [2] a4 7c [2] a6 7d [2] bd 7b [2] a1 7c [2] bd 53 }

  condition:
    any of them
}