rule TTP_XOR_QUAD_CurrentVersionRun_d07e {
  strings:
    $key_d07e = { 83 11 [2] a7 1f [2] 8c 33 [2] a2 11 [2] b6 0a [2] b9 10 [2] a7 0d [2] a5 0c [2] be 0a [2] a2 0d [2] be 22 }

  condition:
    any of them
}