rule TTP_XOR_QUAD_CurrentVersionRun_d312 {
  strings:
    $key_d312 = { 80 7d [2] a4 73 [2] 8f 5f [2] a1 7d [2] b5 66 [2] ba 7c [2] a4 61 [2] a6 60 [2] bd 66 [2] a1 61 [2] bd 4e }

  condition:
    any of them
}