rule TTP_XOR_WriteProcessMemory_e5e4 {
  strings:
    $key_e5e4 = { b2 96 [2] 80 b4 [2] 86 81 [2] a8 81 [2] 97 9d }

  condition:
    any of them
}