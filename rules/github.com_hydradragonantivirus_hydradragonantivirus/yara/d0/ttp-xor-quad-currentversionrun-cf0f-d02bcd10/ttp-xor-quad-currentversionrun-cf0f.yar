rule TTP_XOR_QUAD_CurrentVersionRun_cf0f {
  strings:
    $key_cf0f = { 9c 60 [2] b8 6e [2] 93 42 [2] bd 60 [2] a9 7b [2] a6 61 [2] b8 7c [2] ba 7d [2] a1 7b [2] bd 7c [2] a1 53 }

  condition:
    any of them
}