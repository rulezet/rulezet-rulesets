rule TTP_XOR_WriteProcessMemory_3e47 {
  strings:
    $key_3e47 = { 69 35 [2] 5b 17 [2] 5d 22 [2] 73 22 [2] 4c 3e }

  condition:
    any of them
}