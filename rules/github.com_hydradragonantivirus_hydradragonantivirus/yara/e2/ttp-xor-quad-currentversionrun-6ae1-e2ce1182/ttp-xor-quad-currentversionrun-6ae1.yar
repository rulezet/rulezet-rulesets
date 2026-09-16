rule TTP_XOR_QUAD_CurrentVersionRun_6ae1 {
  strings:
    $key_6ae1 = { 39 8e [2] 1d 80 [2] 36 ac [2] 18 8e [2] 0c 95 [2] 03 8f [2] 1d 92 [2] 1f 93 [2] 04 95 [2] 18 92 [2] 04 bd }

  condition:
    any of them
}