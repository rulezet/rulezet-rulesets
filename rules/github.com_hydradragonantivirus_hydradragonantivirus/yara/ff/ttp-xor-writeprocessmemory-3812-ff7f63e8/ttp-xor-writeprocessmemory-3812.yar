rule TTP_XOR_WriteProcessMemory_3812 {
  strings:
    $key_3812 = { 6f 60 [2] 5d 42 [2] 5b 77 [2] 75 77 [2] 4a 6b }

  condition:
    any of them
}