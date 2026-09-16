rule TTP_XOR_QUAD_CurrentVersionRun_d06d {
  strings:
    $key_d06d = { 83 02 [2] a7 0c [2] 8c 20 [2] a2 02 [2] b6 19 [2] b9 03 [2] a7 1e [2] a5 1f [2] be 19 [2] a2 1e [2] be 31 }

  condition:
    any of them
}