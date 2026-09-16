rule TTP_XOR_QUAD_CurrentVersionRun_2631 {
  strings:
    $key_2631 = { 75 5e [2] 51 50 [2] 7a 7c [2] 54 5e [2] 40 45 [2] 4f 5f [2] 51 42 [2] 53 43 [2] 48 45 [2] 54 42 [2] 48 6d }

  condition:
    any of them
}