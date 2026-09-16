rule TTP_XOR_QUAD_CurrentVersionRun_6bec {
  strings:
    $key_6bec = { 38 83 [2] 1c 8d [2] 37 a1 [2] 19 83 [2] 0d 98 [2] 02 82 [2] 1c 9f [2] 1e 9e [2] 05 98 [2] 19 9f [2] 05 b0 }

  condition:
    any of them
}