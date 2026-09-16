rule TTP_XOR_QUAD_CurrentVersionRun_35f7 {
  strings:
    $key_35f7 = { 66 98 [2] 42 96 [2] 69 ba [2] 47 98 [2] 53 83 [2] 5c 99 [2] 42 84 [2] 40 85 [2] 5b 83 [2] 47 84 [2] 5b ab }

  condition:
    any of them
}