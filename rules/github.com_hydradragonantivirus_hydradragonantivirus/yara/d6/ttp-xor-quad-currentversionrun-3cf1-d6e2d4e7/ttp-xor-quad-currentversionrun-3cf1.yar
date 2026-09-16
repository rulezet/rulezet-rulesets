rule TTP_XOR_QUAD_CurrentVersionRun_3cf1 {
  strings:
    $key_3cf1 = { 6f 9e [2] 4b 90 [2] 60 bc [2] 4e 9e [2] 5a 85 [2] 55 9f [2] 4b 82 [2] 49 83 [2] 52 85 [2] 4e 82 [2] 52 ad }

  condition:
    any of them
}