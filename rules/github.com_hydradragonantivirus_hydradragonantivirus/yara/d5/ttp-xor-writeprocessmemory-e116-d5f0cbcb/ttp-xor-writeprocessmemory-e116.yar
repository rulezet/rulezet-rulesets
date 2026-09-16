rule TTP_XOR_WriteProcessMemory_e116 {
  strings:
    $key_e116 = { b6 64 [2] 84 46 [2] 82 73 [2] ac 73 [2] 93 6f }

  condition:
    any of them
}