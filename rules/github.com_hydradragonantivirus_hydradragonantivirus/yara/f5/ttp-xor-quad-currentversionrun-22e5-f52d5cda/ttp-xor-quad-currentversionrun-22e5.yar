rule TTP_XOR_QUAD_CurrentVersionRun_22e5 {
  strings:
    $key_22e5 = { 71 8a [2] 55 84 [2] 7e a8 [2] 50 8a [2] 44 91 [2] 4b 8b [2] 55 96 [2] 57 97 [2] 4c 91 [2] 50 96 [2] 4c b9 }

  condition:
    any of them
}