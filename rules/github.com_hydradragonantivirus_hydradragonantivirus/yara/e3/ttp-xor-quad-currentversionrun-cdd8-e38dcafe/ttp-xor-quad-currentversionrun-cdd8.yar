rule TTP_XOR_QUAD_CurrentVersionRun_cdd8 {
  strings:
    $key_cdd8 = { 9e b7 [2] ba b9 [2] 91 95 [2] bf b7 [2] ab ac [2] a4 b6 [2] ba ab [2] b8 aa [2] a3 ac [2] bf ab [2] a3 84 }

  condition:
    any of them
}