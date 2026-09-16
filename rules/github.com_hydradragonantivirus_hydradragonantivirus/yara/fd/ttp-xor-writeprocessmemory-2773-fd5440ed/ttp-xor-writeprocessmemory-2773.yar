rule TTP_XOR_WriteProcessMemory_2773 {
  strings:
    $key_2773 = { 70 01 [2] 42 23 [2] 44 16 [2] 6a 16 [2] 55 0a }

  condition:
    any of them
}