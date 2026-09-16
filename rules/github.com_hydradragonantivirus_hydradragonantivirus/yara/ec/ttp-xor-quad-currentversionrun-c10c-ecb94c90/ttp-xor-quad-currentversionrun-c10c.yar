rule TTP_XOR_QUAD_CurrentVersionRun_c10c {
  strings:
    $key_c10c = { 92 63 [2] b6 6d [2] 9d 41 [2] b3 63 [2] a7 78 [2] a8 62 [2] b6 7f [2] b4 7e [2] af 78 [2] b3 7f [2] af 50 }

  condition:
    any of them
}