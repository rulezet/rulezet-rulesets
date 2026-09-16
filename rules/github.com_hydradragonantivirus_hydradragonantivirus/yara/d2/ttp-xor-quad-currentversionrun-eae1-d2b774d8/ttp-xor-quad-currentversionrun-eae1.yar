rule TTP_XOR_QUAD_CurrentVersionRun_eae1 {
  strings:
    $key_eae1 = { b9 8e [2] 9d 80 [2] b6 ac [2] 98 8e [2] 8c 95 [2] 83 8f [2] 9d 92 [2] 9f 93 [2] 84 95 [2] 98 92 [2] 84 bd }

  condition:
    any of them
}