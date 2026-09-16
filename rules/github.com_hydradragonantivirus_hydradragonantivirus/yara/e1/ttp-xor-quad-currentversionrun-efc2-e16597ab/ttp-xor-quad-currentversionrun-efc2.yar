rule TTP_XOR_QUAD_CurrentVersionRun_efc2 {
  strings:
    $key_efc2 = { bc ad [2] 98 a3 [2] b3 8f [2] 9d ad [2] 89 b6 [2] 86 ac [2] 98 b1 [2] 9a b0 [2] 81 b6 [2] 9d b1 [2] 81 9e }

  condition:
    any of them
}