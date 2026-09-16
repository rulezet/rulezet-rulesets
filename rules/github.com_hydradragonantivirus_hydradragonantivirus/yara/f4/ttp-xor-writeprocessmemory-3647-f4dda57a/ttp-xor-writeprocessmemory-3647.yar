rule TTP_XOR_WriteProcessMemory_3647 {
  strings:
    $key_3647 = { 61 35 [2] 53 17 [2] 55 22 [2] 7b 22 [2] 44 3e }

  condition:
    any of them
}