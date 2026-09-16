rule TTP_XOR_QUAD_CurrentVersionRun_fc30 {
  strings:
    $key_fc30 = { af 5f [2] 8b 51 [2] a0 7d [2] 8e 5f [2] 9a 44 [2] 95 5e [2] 8b 43 [2] 89 42 [2] 92 44 [2] 8e 43 [2] 92 6c }

  condition:
    any of them
}