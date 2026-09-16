rule TTP_XOR_QUAD_CurrentVersionRun_d02d {
  strings:
    $key_d02d = { 83 42 [2] a7 4c [2] 8c 60 [2] a2 42 [2] b6 59 [2] b9 43 [2] a7 5e [2] a5 5f [2] be 59 [2] a2 5e [2] be 71 }

  condition:
    any of them
}