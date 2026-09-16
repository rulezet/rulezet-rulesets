rule TTP_XOR_QUAD_CurrentVersionRun_fbec {
  strings:
    $key_fbec = { a8 83 [2] 8c 8d [2] a7 a1 [2] 89 83 [2] 9d 98 [2] 92 82 [2] 8c 9f [2] 8e 9e [2] 95 98 [2] 89 9f [2] 95 b0 }

  condition:
    any of them
}