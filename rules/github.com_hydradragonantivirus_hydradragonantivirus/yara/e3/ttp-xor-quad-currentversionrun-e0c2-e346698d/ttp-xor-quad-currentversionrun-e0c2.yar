rule TTP_XOR_QUAD_CurrentVersionRun_e0c2 {
  strings:
    $key_e0c2 = { b3 ad [2] 97 a3 [2] bc 8f [2] 92 ad [2] 86 b6 [2] 89 ac [2] 97 b1 [2] 95 b0 [2] 8e b6 [2] 92 b1 [2] 8e 9e }

  condition:
    any of them
}