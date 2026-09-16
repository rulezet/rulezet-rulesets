rule TTP_XOR_QUAD_CurrentVersionRun_dd21 {
  strings:
    $key_dd21 = { 8e 4e [2] aa 40 [2] 81 6c [2] af 4e [2] bb 55 [2] b4 4f [2] aa 52 [2] a8 53 [2] b3 55 [2] af 52 [2] b3 7d }

  condition:
    any of them
}