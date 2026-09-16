rule TTP_XOR_QUAD_CurrentVersionRun_ccd8 {
  strings:
    $key_ccd8 = { 9f b7 [2] bb b9 [2] 90 95 [2] be b7 [2] aa ac [2] a5 b6 [2] bb ab [2] b9 aa [2] a2 ac [2] be ab [2] a2 84 }

  condition:
    any of them
}