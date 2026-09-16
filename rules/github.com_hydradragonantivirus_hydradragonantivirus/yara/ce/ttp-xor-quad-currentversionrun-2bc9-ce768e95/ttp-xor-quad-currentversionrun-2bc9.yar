rule TTP_XOR_QUAD_CurrentVersionRun_2bc9 {
  strings:
    $key_2bc9 = { 78 a6 [2] 5c a8 [2] 77 84 [2] 59 a6 [2] 4d bd [2] 42 a7 [2] 5c ba [2] 5e bb [2] 45 bd [2] 59 ba [2] 45 95 }

  condition:
    any of them
}