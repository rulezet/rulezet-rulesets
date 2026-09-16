rule TTP_XOR_QUAD_CurrentVersionRun_cdc2 {
  strings:
    $key_cdc2 = { 9e ad [2] ba a3 [2] 91 8f [2] bf ad [2] ab b6 [2] a4 ac [2] ba b1 [2] b8 b0 [2] a3 b6 [2] bf b1 [2] a3 9e }

  condition:
    any of them
}