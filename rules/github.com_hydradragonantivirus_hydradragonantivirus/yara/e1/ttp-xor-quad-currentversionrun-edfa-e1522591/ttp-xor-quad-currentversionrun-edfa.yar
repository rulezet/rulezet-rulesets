rule TTP_XOR_QUAD_CurrentVersionRun_edfa {
  strings:
    $key_edfa = { be 95 [2] 9a 9b [2] b1 b7 [2] 9f 95 [2] 8b 8e [2] 84 94 [2] 9a 89 [2] 98 88 [2] 83 8e [2] 9f 89 [2] 83 a6 }

  condition:
    any of them
}