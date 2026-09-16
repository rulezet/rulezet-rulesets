rule TTP_XOR_WriteProcessMemory_2a37 {
  strings:
    $key_2a37 = { 7d 45 [2] 4f 67 [2] 49 52 [2] 67 52 [2] 58 4e }

  condition:
    any of them
}