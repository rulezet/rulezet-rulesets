rule TTP_XOR_WriteProcessMemory_ea37 {
  strings:
    $key_ea37 = { bd 45 [2] 8f 67 [2] 89 52 [2] a7 52 [2] 98 4e }

  condition:
    any of them
}