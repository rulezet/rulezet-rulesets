rule TTP_XOR_QUAD_CurrentVersionRun_2731 {
  strings:
    $key_2731 = { 74 5e [2] 50 50 [2] 7b 7c [2] 55 5e [2] 41 45 [2] 4e 5f [2] 50 42 [2] 52 43 [2] 49 45 [2] 55 42 [2] 49 6d }

  condition:
    any of them
}