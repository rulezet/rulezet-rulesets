rule TTP_XOR_QUAD_CurrentVersionRun_07f0 {
  strings:
    $key_07f0 = { 54 9f [2] 70 91 [2] 5b bd [2] 75 9f [2] 61 84 [2] 6e 9e [2] 70 83 [2] 72 82 [2] 69 84 [2] 75 83 [2] 69 ac }

  condition:
    any of them
}