rule TTP_XOR_QUAD_CurrentVersionRun_d00d {
  strings:
    $key_d00d = { 83 62 [2] a7 6c [2] 8c 40 [2] a2 62 [2] b6 79 [2] b9 63 [2] a7 7e [2] a5 7f [2] be 79 [2] a2 7e [2] be 51 }

  condition:
    any of them
}