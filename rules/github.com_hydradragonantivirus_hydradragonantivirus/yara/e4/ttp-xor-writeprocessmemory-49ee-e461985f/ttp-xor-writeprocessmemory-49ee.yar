rule TTP_XOR_WriteProcessMemory_49ee {
  strings:
    $key_49ee = { 1e 9c [2] 2c be [2] 2a 8b [2] 04 8b [2] 3b 97 }

  condition:
    any of them
}