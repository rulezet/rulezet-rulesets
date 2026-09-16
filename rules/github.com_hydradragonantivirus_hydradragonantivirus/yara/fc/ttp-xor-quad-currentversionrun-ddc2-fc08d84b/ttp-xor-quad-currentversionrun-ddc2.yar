rule TTP_XOR_QUAD_CurrentVersionRun_ddc2 {
  strings:
    $key_ddc2 = { 8e ad [2] aa a3 [2] 81 8f [2] af ad [2] bb b6 [2] b4 ac [2] aa b1 [2] a8 b0 [2] b3 b6 [2] af b1 [2] b3 9e }

  condition:
    any of them
}