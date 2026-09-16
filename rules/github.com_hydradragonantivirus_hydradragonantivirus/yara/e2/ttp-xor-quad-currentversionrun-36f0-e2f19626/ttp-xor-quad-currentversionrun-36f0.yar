rule TTP_XOR_QUAD_CurrentVersionRun_36f0 {
  strings:
    $key_36f0 = { 65 9f [2] 41 91 [2] 6a bd [2] 44 9f [2] 50 84 [2] 5f 9e [2] 41 83 [2] 43 82 [2] 58 84 [2] 44 83 [2] 58 ac }

  condition:
    any of them
}