rule TTP_XOR_WriteProcessMemory_2bf1 {
  strings:
    $key_2bf1 = { 7c 83 [2] 4e a1 [2] 48 94 [2] 66 94 [2] 59 88 }

  condition:
    any of them
}