rule TTP_XOR_QUAD_CurrentVersionRun_2bfd {
  strings:
    $key_2bfd = { 78 92 [2] 5c 9c [2] 77 b0 [2] 59 92 [2] 4d 89 [2] 42 93 [2] 5c 8e [2] 5e 8f [2] 45 89 [2] 59 8e [2] 45 a1 }

  condition:
    any of them
}