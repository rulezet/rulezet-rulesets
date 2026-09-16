rule TTP_XOR_QUAD_CurrentVersionRun_c1ec {
  strings:
    $key_c1ec = { 92 83 [2] b6 8d [2] 9d a1 [2] b3 83 [2] a7 98 [2] a8 82 [2] b6 9f [2] b4 9e [2] af 98 [2] b3 9f [2] af b0 }

  condition:
    any of them
}