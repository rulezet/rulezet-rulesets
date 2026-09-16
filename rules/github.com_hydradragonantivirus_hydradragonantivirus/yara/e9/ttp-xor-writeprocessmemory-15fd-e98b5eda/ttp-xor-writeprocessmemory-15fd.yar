rule TTP_XOR_WriteProcessMemory_15fd {
  strings:
    $key_15fd = { 42 8f [2] 70 ad [2] 76 98 [2] 58 98 [2] 67 84 }

  condition:
    any of them
}