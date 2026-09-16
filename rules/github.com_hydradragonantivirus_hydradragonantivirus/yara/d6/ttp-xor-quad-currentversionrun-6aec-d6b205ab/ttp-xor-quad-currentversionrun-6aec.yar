rule TTP_XOR_QUAD_CurrentVersionRun_6aec {
  strings:
    $key_6aec = { 39 83 [2] 1d 8d [2] 36 a1 [2] 18 83 [2] 0c 98 [2] 03 82 [2] 1d 9f [2] 1f 9e [2] 04 98 [2] 18 9f [2] 04 b0 }

  condition:
    any of them
}