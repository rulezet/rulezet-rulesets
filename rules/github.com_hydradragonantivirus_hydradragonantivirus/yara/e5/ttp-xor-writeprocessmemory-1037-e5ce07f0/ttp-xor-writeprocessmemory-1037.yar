rule TTP_XOR_WriteProcessMemory_1037 {
  strings:
    $key_1037 = { 47 45 [2] 75 67 [2] 73 52 [2] 5d 52 [2] 62 4e }

  condition:
    any of them
}