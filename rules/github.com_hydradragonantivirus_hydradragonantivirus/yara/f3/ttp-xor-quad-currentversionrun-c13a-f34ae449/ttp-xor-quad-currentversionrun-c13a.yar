rule TTP_XOR_QUAD_CurrentVersionRun_c13a {
  strings:
    $key_c13a = { 92 55 [2] b6 5b [2] 9d 77 [2] b3 55 [2] a7 4e [2] a8 54 [2] b6 49 [2] b4 48 [2] af 4e [2] b3 49 [2] af 66 }

  condition:
    any of them
}