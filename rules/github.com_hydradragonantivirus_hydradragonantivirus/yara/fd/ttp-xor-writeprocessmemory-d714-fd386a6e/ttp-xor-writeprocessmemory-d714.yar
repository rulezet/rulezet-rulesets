rule TTP_XOR_WriteProcessMemory_d714 {
  strings:
    $key_d714 = { 80 66 [2] b2 44 [2] b4 71 [2] 9a 71 [2] a5 6d }

  condition:
    any of them
}