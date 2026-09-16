rule TTP_XOR_QUAD_CurrentVersionRun_c11f {
  strings:
    $key_c11f = { 92 70 [2] b6 7e [2] 9d 52 [2] b3 70 [2] a7 6b [2] a8 71 [2] b6 6c [2] b4 6d [2] af 6b [2] b3 6c [2] af 43 }

  condition:
    any of them
}