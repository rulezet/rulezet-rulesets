rule TTP_XOR_WriteProcessMemory_ea45 {
  strings:
    $key_ea45 = { bd 37 [2] 8f 15 [2] 89 20 [2] a7 20 [2] 98 3c }

  condition:
    any of them
}