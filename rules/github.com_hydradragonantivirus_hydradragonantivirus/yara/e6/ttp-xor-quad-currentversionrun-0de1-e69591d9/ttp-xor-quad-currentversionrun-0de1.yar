rule TTP_XOR_QUAD_CurrentVersionRun_0de1 {
  strings:
    $key_0de1 = { 5e 8e [2] 7a 80 [2] 51 ac [2] 7f 8e [2] 6b 95 [2] 64 8f [2] 7a 92 [2] 78 93 [2] 63 95 [2] 7f 92 [2] 63 bd }

  condition:
    any of them
}