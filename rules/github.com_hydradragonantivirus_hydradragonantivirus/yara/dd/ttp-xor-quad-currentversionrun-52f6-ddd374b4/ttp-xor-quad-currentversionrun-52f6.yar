rule TTP_XOR_QUAD_CurrentVersionRun_52f6 {
  strings:
    $key_52f6 = { 01 99 [2] 25 97 [2] 0e bb [2] 20 99 [2] 34 82 [2] 3b 98 [2] 25 85 [2] 27 84 [2] 3c 82 [2] 20 85 [2] 3c aa }

  condition:
    any of them
}