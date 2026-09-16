rule TTP_XOR_QUAD_CurrentVersionRun_c10d {
  strings:
    $key_c10d = { 92 62 [2] b6 6c [2] 9d 40 [2] b3 62 [2] a7 79 [2] a8 63 [2] b6 7e [2] b4 7f [2] af 79 [2] b3 7e [2] af 51 }

  condition:
    any of them
}