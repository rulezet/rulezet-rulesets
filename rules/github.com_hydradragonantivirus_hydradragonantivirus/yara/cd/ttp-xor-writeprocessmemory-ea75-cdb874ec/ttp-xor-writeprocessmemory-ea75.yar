rule TTP_XOR_WriteProcessMemory_ea75 {
  strings:
    $key_ea75 = { bd 07 [2] 8f 25 [2] 89 10 [2] a7 10 [2] 98 0c }

  condition:
    any of them
}