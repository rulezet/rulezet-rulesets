rule TTP_XOR_QUAD_CurrentVersionRun_c13f {
  strings:
    $key_c13f = { 92 50 [2] b6 5e [2] 9d 72 [2] b3 50 [2] a7 4b [2] a8 51 [2] b6 4c [2] b4 4d [2] af 4b [2] b3 4c [2] af 63 }

  condition:
    any of them
}