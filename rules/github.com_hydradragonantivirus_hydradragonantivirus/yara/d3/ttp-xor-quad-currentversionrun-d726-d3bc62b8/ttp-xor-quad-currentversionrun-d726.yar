rule TTP_XOR_QUAD_CurrentVersionRun_d726 {
  strings:
    $key_d726 = { 84 49 [2] a0 47 [2] 8b 6b [2] a5 49 [2] b1 52 [2] be 48 [2] a0 55 [2] a2 54 [2] b9 52 [2] a5 55 [2] b9 7a }

  condition:
    any of them
}