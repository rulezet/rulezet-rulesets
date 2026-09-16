rule TTP_XOR_QUAD_CurrentVersionRun_3700 {
  strings:
    $key_3700 = { 64 6f [2] 40 61 [2] 6b 4d [2] 45 6f [2] 51 74 [2] 5e 6e [2] 40 73 [2] 42 72 [2] 59 74 [2] 45 73 [2] 59 5c }

  condition:
    any of them
}