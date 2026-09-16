rule TTP_XOR_QUAD_CurrentVersionRun_2606 {
  strings:
    $key_2606 = { 75 69 [2] 51 67 [2] 7a 4b [2] 54 69 [2] 40 72 [2] 4f 68 [2] 51 75 [2] 53 74 [2] 48 72 [2] 54 75 [2] 48 5a }

  condition:
    any of them
}