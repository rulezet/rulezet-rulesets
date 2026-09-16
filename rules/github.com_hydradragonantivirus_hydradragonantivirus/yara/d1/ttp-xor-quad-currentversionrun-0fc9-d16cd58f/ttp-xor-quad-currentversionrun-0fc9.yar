rule TTP_XOR_QUAD_CurrentVersionRun_0fc9 {
  strings:
    $key_0fc9 = { 5c a6 [2] 78 a8 [2] 53 84 [2] 7d a6 [2] 69 bd [2] 66 a7 [2] 78 ba [2] 7a bb [2] 61 bd [2] 7d ba [2] 61 95 }

  condition:
    any of them
}