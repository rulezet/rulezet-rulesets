rule TTP_XOR_QUAD_CurrentVersionRun_cdc4 {
  strings:
    $key_cdc4 = { 9e ab [2] ba a5 [2] 91 89 [2] bf ab [2] ab b0 [2] a4 aa [2] ba b7 [2] b8 b6 [2] a3 b0 [2] bf b7 [2] a3 98 }

  condition:
    any of them
}