rule TTP_XOR_QUAD_CurrentVersionRun_c110 {
  strings:
    $key_c110 = { 92 7f [2] b6 71 [2] 9d 5d [2] b3 7f [2] a7 64 [2] a8 7e [2] b6 63 [2] b4 62 [2] af 64 [2] b3 63 [2] af 4c }

  condition:
    any of them
}