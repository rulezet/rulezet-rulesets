rule TTP_XOR_WriteProcessMemory_2be7 {
  strings:
    $key_2be7 = { 7c 95 [2] 4e b7 [2] 48 82 [2] 66 82 [2] 59 9e }

  condition:
    any of them
}