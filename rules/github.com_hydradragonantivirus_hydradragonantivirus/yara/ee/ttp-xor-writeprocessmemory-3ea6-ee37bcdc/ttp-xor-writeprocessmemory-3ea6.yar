rule TTP_XOR_WriteProcessMemory_3ea6 {
  strings:
    $key_3ea6 = { 69 d4 [2] 5b f6 [2] 5d c3 [2] 73 c3 [2] 4c df }

  condition:
    any of them
}