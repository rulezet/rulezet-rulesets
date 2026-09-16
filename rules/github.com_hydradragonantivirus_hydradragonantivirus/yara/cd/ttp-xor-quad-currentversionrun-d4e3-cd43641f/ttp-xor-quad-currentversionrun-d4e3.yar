rule TTP_XOR_QUAD_CurrentVersionRun_d4e3 {
  strings:
    $key_d4e3 = { 87 8c [2] a3 82 [2] 88 ae [2] a6 8c [2] b2 97 [2] bd 8d [2] a3 90 [2] a1 91 [2] ba 97 [2] a6 90 [2] ba bf }

  condition:
    any of them
}