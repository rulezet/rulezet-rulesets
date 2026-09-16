rule TTP_XOR_QUAD_CurrentVersionRun_d70b {
  strings:
    $key_d70b = { 84 64 [2] a0 6a [2] 8b 46 [2] a5 64 [2] b1 7f [2] be 65 [2] a0 78 [2] a2 79 [2] b9 7f [2] a5 78 [2] b9 57 }

  condition:
    any of them
}