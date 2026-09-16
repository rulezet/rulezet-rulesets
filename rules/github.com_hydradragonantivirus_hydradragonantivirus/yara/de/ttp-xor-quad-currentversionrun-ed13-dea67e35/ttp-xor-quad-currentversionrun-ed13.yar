rule TTP_XOR_QUAD_CurrentVersionRun_ed13 {
  strings:
    $key_ed13 = { be 7c [2] 9a 72 [2] b1 5e [2] 9f 7c [2] 8b 67 [2] 84 7d [2] 9a 60 [2] 98 61 [2] 83 67 [2] 9f 60 [2] 83 4f }

  condition:
    any of them
}