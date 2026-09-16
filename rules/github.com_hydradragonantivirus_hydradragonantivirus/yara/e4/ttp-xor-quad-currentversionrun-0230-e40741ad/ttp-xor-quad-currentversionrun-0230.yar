rule TTP_XOR_QUAD_CurrentVersionRun_0230 {
  strings:
    $key_0230 = { 51 5f [2] 75 51 [2] 5e 7d [2] 70 5f [2] 64 44 [2] 6b 5e [2] 75 43 [2] 77 42 [2] 6c 44 [2] 70 43 [2] 6c 6c }

  condition:
    any of them
}