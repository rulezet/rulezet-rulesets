rule TTP_XOR_WriteProcessMemory_eef6 {
  strings:
    $key_eef6 = { b9 84 [2] 8b a6 [2] 8d 93 [2] a3 93 [2] 9c 8f }

  condition:
    any of them
}