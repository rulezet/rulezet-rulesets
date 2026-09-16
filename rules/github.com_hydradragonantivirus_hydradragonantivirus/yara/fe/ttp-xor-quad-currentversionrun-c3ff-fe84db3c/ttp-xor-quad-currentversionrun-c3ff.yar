rule TTP_XOR_QUAD_CurrentVersionRun_c3ff {
  strings:
    $key_c3ff = { 90 90 [2] b4 9e [2] 9f b2 [2] b1 90 [2] a5 8b [2] aa 91 [2] b4 8c [2] b6 8d [2] ad 8b [2] b1 8c [2] ad a3 }

  condition:
    any of them
}