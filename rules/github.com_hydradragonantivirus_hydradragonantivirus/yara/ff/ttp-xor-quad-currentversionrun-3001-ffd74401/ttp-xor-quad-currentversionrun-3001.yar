rule TTP_XOR_QUAD_CurrentVersionRun_3001 {
  strings:
    $key_3001 = { 63 6e [2] 47 60 [2] 6c 4c [2] 42 6e [2] 56 75 [2] 59 6f [2] 47 72 [2] 45 73 [2] 5e 75 [2] 42 72 [2] 5e 5d }

  condition:
    any of them
}