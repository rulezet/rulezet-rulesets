rule TTP_XOR_WriteProcessMemory_ea35 {
  strings:
    $key_ea35 = { bd 47 [2] 8f 65 [2] 89 50 [2] a7 50 [2] 98 4c }

  condition:
    any of them
}