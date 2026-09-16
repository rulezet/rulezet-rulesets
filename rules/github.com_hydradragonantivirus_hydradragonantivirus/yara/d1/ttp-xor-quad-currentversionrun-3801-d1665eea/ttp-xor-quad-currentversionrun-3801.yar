rule TTP_XOR_QUAD_CurrentVersionRun_3801 {
  strings:
    $key_3801 = { 6b 6e [2] 4f 60 [2] 64 4c [2] 4a 6e [2] 5e 75 [2] 51 6f [2] 4f 72 [2] 4d 73 [2] 56 75 [2] 4a 72 [2] 56 5d }

  condition:
    any of them
}