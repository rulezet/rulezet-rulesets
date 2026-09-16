rule TTP_XOR_QUAD_CurrentVersionRun_c6e2 {
  strings:
    $key_c6e2 = { 95 8d [2] b1 83 [2] 9a af [2] b4 8d [2] a0 96 [2] af 8c [2] b1 91 [2] b3 90 [2] a8 96 [2] b4 91 [2] a8 be }

  condition:
    any of them
}