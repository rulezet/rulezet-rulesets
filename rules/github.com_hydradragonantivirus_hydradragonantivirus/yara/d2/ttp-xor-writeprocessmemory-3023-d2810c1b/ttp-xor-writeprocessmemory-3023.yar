rule TTP_XOR_WriteProcessMemory_3023 {
  strings:
    $key_3023 = { 67 51 [2] 55 73 [2] 53 46 [2] 7d 46 [2] 42 5a }

  condition:
    any of them
}