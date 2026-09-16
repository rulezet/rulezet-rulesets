rule TTP_XOR_QUAD_CurrentVersionRun_64f0 {
  strings:
    $key_64f0 = { 37 9f [2] 13 91 [2] 38 bd [2] 16 9f [2] 02 84 [2] 0d 9e [2] 13 83 [2] 11 82 [2] 0a 84 [2] 16 83 [2] 0a ac }

  condition:
    any of them
}