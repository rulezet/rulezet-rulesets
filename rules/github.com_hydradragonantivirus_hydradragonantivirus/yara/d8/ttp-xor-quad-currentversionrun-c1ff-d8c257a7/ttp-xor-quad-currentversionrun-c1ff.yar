rule TTP_XOR_QUAD_CurrentVersionRun_c1ff {
  strings:
    $key_c1ff = { 92 90 [2] b6 9e [2] 9d b2 [2] b3 90 [2] a7 8b [2] a8 91 [2] b6 8c [2] b4 8d [2] af 8b [2] b3 8c [2] af a3 }

  condition:
    any of them
}