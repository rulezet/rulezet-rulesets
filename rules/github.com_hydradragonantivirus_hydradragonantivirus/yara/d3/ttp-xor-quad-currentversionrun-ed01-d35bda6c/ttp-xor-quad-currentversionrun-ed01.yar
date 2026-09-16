rule TTP_XOR_QUAD_CurrentVersionRun_ed01 {
  strings:
    $key_ed01 = { be 6e [2] 9a 60 [2] b1 4c [2] 9f 6e [2] 8b 75 [2] 84 6f [2] 9a 72 [2] 98 73 [2] 83 75 [2] 9f 72 [2] 83 5d }

  condition:
    any of them
}