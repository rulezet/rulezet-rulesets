rule TTP_XOR_QUAD_CurrentVersionRun_dd2f {
  strings:
    $key_dd2f = { 8e 40 [2] aa 4e [2] 81 62 [2] af 40 [2] bb 5b [2] b4 41 [2] aa 5c [2] a8 5d [2] b3 5b [2] af 5c [2] b3 73 }

  condition:
    any of them
}