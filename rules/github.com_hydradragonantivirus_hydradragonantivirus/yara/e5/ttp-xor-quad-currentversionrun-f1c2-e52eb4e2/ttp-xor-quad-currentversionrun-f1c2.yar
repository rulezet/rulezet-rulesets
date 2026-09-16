rule TTP_XOR_QUAD_CurrentVersionRun_f1c2 {
  strings:
    $key_f1c2 = { a2 ad [2] 86 a3 [2] ad 8f [2] 83 ad [2] 97 b6 [2] 98 ac [2] 86 b1 [2] 84 b0 [2] 9f b6 [2] 83 b1 [2] 9f 9e }

  condition:
    any of them
}