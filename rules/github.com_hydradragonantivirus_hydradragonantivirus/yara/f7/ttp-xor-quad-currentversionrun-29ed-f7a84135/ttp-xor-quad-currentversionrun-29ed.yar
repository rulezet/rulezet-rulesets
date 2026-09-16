rule TTP_XOR_QUAD_CurrentVersionRun_29ed {
  strings:
    $key_29ed = { 7a 82 [2] 5e 8c [2] 75 a0 [2] 5b 82 [2] 4f 99 [2] 40 83 [2] 5e 9e [2] 5c 9f [2] 47 99 [2] 5b 9e [2] 47 b1 }

  condition:
    any of them
}