rule TTP_XOR_QUAD_CurrentVersionRun_5731 {
  strings:
    $key_5731 = { 04 5e [2] 20 50 [2] 0b 7c [2] 25 5e [2] 31 45 [2] 3e 5f [2] 20 42 [2] 22 43 [2] 39 45 [2] 25 42 [2] 39 6d }

  condition:
    any of them
}