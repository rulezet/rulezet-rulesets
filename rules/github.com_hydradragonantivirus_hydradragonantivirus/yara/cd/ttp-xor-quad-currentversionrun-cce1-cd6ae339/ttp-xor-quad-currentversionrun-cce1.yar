rule TTP_XOR_QUAD_CurrentVersionRun_cce1 {
  strings:
    $key_cce1 = { 9f 8e [2] bb 80 [2] 90 ac [2] be 8e [2] aa 95 [2] a5 8f [2] bb 92 [2] b9 93 [2] a2 95 [2] be 92 [2] a2 bd }

  condition:
    any of them
}