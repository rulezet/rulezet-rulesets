rule TTP_XOR_WriteProcessMemory_ea23 {
  strings:
    $key_ea23 = { bd 51 [2] 8f 73 [2] 89 46 [2] a7 46 [2] 98 5a }

  condition:
    any of them
}