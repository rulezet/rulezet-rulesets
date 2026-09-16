rule TTP_XOR_QUAD_CurrentVersionRun_d016 {
  strings:
    $key_d016 = { 83 79 [2] a7 77 [2] 8c 5b [2] a2 79 [2] b6 62 [2] b9 78 [2] a7 65 [2] a5 64 [2] be 62 [2] a2 65 [2] be 4a }

  condition:
    any of them
}