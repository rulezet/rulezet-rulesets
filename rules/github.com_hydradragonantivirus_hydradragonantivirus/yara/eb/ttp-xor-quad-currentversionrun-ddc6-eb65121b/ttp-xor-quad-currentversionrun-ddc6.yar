rule TTP_XOR_QUAD_CurrentVersionRun_ddc6 {
  strings:
    $key_ddc6 = { 8e a9 [2] aa a7 [2] 81 8b [2] af a9 [2] bb b2 [2] b4 a8 [2] aa b5 [2] a8 b4 [2] b3 b2 [2] af b5 [2] b3 9a }

  condition:
    any of them
}