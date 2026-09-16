rule TTP_XOR_QUAD_CurrentVersionRun_2bec {
  strings:
    $key_2bec = { 78 83 [2] 5c 8d [2] 77 a1 [2] 59 83 [2] 4d 98 [2] 42 82 [2] 5c 9f [2] 5e 9e [2] 45 98 [2] 59 9f [2] 45 b0 }

  condition:
    any of them
}