rule TTP_XOR_QUAD_CurrentVersionRun_1de1 {
  strings:
    $key_1de1 = { 4e 8e [2] 6a 80 [2] 41 ac [2] 6f 8e [2] 7b 95 [2] 74 8f [2] 6a 92 [2] 68 93 [2] 73 95 [2] 6f 92 [2] 73 bd }

  condition:
    any of them
}