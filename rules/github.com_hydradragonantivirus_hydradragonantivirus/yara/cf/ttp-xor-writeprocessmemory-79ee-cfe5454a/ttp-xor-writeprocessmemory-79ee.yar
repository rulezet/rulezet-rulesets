rule TTP_XOR_WriteProcessMemory_79ee {
  strings:
    $key_79ee = { 2e 9c [2] 1c be [2] 1a 8b [2] 34 8b [2] 0b 97 }

  condition:
    any of them
}