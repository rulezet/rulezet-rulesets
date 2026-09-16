rule TTP_XOR_QUAD_CurrentVersionRun_d03a {
  strings:
    $key_d03a = { 83 55 [2] a7 5b [2] 8c 77 [2] a2 55 [2] b6 4e [2] b9 54 [2] a7 49 [2] a5 48 [2] be 4e [2] a2 49 [2] be 66 }

  condition:
    any of them
}