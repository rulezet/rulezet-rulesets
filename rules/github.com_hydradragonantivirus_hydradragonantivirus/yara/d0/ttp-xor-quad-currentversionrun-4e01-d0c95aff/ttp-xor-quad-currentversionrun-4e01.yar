rule TTP_XOR_QUAD_CurrentVersionRun_4e01 {
  strings:
    $key_4e01 = { 1d 6e [2] 39 60 [2] 12 4c [2] 3c 6e [2] 28 75 [2] 27 6f [2] 39 72 [2] 3b 73 [2] 20 75 [2] 3c 72 [2] 20 5d }

  condition:
    any of them
}