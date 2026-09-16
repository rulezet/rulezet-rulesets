rule TTP_XOR_QUAD_CurrentVersionRun_2706 {
  strings:
    $key_2706 = { 74 69 [2] 50 67 [2] 7b 4b [2] 55 69 [2] 41 72 [2] 4e 68 [2] 50 75 [2] 52 74 [2] 49 72 [2] 55 75 [2] 49 5a }

  condition:
    any of them
}