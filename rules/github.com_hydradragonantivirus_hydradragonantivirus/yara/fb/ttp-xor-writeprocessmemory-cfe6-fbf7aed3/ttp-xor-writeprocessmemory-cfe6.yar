rule TTP_XOR_WriteProcessMemory_cfe6 {
  strings:
    $key_cfe6 = { 98 94 [2] aa b6 [2] ac 83 [2] 82 83 [2] bd 9f }

  condition:
    any of them
}