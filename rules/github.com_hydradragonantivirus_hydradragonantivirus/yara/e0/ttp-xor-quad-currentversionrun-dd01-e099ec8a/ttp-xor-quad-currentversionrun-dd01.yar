rule TTP_XOR_QUAD_CurrentVersionRun_dd01 {
  strings:
    $key_dd01 = { 8e 6e [2] aa 60 [2] 81 4c [2] af 6e [2] bb 75 [2] b4 6f [2] aa 72 [2] a8 73 [2] b3 75 [2] af 72 [2] b3 5d }

  condition:
    any of them
}