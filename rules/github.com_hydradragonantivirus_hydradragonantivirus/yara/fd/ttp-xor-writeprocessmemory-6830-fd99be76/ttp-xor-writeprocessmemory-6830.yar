rule TTP_XOR_WriteProcessMemory_6830 {
  strings:
    $key_6830 = { 3f 42 [2] 0d 60 [2] 0b 55 [2] 25 55 [2] 1a 49 }

  condition:
    any of them
}