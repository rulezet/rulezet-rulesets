rule TTP_XOR_QUAD_CurrentVersionRun_12f6 {
  strings:
    $key_12f6 = { 41 99 [2] 65 97 [2] 4e bb [2] 60 99 [2] 74 82 [2] 7b 98 [2] 65 85 [2] 67 84 [2] 7c 82 [2] 60 85 [2] 7c aa }

  condition:
    any of them
}