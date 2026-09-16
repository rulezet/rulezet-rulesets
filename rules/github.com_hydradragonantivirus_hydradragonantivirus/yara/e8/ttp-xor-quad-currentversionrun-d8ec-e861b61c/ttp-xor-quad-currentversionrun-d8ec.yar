rule TTP_XOR_QUAD_CurrentVersionRun_d8ec {
  strings:
    $key_d8ec = { 8b 83 [2] af 8d [2] 84 a1 [2] aa 83 [2] be 98 [2] b1 82 [2] af 9f [2] ad 9e [2] b6 98 [2] aa 9f [2] b6 b0 }

  condition:
    any of them
}