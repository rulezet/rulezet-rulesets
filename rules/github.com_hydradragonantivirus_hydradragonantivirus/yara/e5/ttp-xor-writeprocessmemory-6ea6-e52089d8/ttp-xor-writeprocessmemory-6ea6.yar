rule TTP_XOR_WriteProcessMemory_6ea6 {
  strings:
    $key_6ea6 = { 39 d4 [2] 0b f6 [2] 0d c3 [2] 23 c3 [2] 1c df }

  condition:
    any of them
}