rule TTP_XOR_QUAD_CurrentVersionRun_3eec {
  strings:
    $key_3eec = { 6d 83 [2] 49 8d [2] 62 a1 [2] 4c 83 [2] 58 98 [2] 57 82 [2] 49 9f [2] 4b 9e [2] 50 98 [2] 4c 9f [2] 50 b0 }

  condition:
    any of them
}