rule TTP_XOR_QUAD_CurrentVersionRun_e541 {
  strings:
    $key_e541 = { b6 2e [2] 92 20 [2] b9 0c [2] 97 2e [2] 83 35 [2] 8c 2f [2] 92 32 [2] 90 33 [2] 8b 35 [2] 97 32 [2] 8b 1d }

  condition:
    any of them
}