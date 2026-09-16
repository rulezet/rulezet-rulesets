rule TTP_XOR_QUAD_CurrentVersionRun_de31 {
  strings:
    $key_de31 = { 8d 5e [2] a9 50 [2] 82 7c [2] ac 5e [2] b8 45 [2] b7 5f [2] a9 42 [2] ab 43 [2] b0 45 [2] ac 42 [2] b0 6d }

  condition:
    any of them
}