rule TTP_XOR_QUAD_CurrentVersionRun_d23c {
  strings:
    $key_d23c = { 81 53 [2] a5 5d [2] 8e 71 [2] a0 53 [2] b4 48 [2] bb 52 [2] a5 4f [2] a7 4e [2] bc 48 [2] a0 4f [2] bc 60 }

  condition:
    any of them
}