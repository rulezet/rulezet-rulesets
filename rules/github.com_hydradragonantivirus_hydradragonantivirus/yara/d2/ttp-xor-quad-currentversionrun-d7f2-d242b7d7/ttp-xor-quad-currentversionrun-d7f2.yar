rule TTP_XOR_QUAD_CurrentVersionRun_d7f2 {
  strings:
    $key_d7f2 = { 84 9d [2] a0 93 [2] 8b bf [2] a5 9d [2] b1 86 [2] be 9c [2] a0 81 [2] a2 80 [2] b9 86 [2] a5 81 [2] b9 ae }

  condition:
    any of them
}