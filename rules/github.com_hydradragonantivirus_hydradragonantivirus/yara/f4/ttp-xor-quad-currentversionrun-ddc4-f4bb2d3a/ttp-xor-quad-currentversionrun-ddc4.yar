rule TTP_XOR_QUAD_CurrentVersionRun_ddc4 {
  strings:
    $key_ddc4 = { 8e ab [2] aa a5 [2] 81 89 [2] af ab [2] bb b0 [2] b4 aa [2] aa b7 [2] a8 b6 [2] b3 b0 [2] af b7 [2] b3 98 }

  condition:
    any of them
}