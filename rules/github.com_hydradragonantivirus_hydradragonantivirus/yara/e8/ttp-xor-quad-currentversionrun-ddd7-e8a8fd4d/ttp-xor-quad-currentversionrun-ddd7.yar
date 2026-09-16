rule TTP_XOR_QUAD_CurrentVersionRun_ddd7 {
  strings:
    $key_ddd7 = { 8e b8 [2] aa b6 [2] 81 9a [2] af b8 [2] bb a3 [2] b4 b9 [2] aa a4 [2] a8 a5 [2] b3 a3 [2] af a4 [2] b3 8b }

  condition:
    any of them
}