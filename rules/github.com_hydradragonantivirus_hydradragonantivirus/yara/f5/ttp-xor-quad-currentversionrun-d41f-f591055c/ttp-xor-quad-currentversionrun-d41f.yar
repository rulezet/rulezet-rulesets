rule TTP_XOR_QUAD_CurrentVersionRun_d41f {
  strings:
    $key_d41f = { 87 70 [2] a3 7e [2] 88 52 [2] a6 70 [2] b2 6b [2] bd 71 [2] a3 6c [2] a1 6d [2] ba 6b [2] a6 6c [2] ba 43 }

  condition:
    any of them
}