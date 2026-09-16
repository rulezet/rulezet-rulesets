rule TTP_XOR_WriteProcessMemory_d304 {
  strings:
    $key_d304 = { 84 76 [2] b6 54 [2] b0 61 [2] 9e 61 [2] a1 7d }

  condition:
    any of them
}