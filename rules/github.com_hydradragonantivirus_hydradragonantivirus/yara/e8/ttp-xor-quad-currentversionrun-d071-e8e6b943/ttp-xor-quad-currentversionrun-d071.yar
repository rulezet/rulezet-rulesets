rule TTP_XOR_QUAD_CurrentVersionRun_d071 {
  strings:
    $key_d071 = { 83 1e [2] a7 10 [2] 8c 3c [2] a2 1e [2] b6 05 [2] b9 1f [2] a7 02 [2] a5 03 [2] be 05 [2] a2 02 [2] be 2d }

  condition:
    any of them
}