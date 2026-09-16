rule TTP_XOR_WriteProcessMemory_8afe {
  strings:
    $key_8afe = { dd 8c [2] ef ae [2] e9 9b [2] c7 9b [2] f8 87 }

  condition:
    any of them
}