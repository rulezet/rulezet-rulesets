rule TTP_XOR_QUAD_CurrentVersionRun_ed31 {
  strings:
    $key_ed31 = { be 5e [2] 9a 50 [2] b1 7c [2] 9f 5e [2] 8b 45 [2] 84 5f [2] 9a 42 [2] 98 43 [2] 83 45 [2] 9f 42 [2] 83 6d }

  condition:
    any of them
}