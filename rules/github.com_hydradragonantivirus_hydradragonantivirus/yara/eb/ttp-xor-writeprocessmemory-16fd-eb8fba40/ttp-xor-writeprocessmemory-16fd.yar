rule TTP_XOR_WriteProcessMemory_16fd {
  strings:
    $key_16fd = { 41 8f [2] 73 ad [2] 75 98 [2] 5b 98 [2] 64 84 }

  condition:
    any of them
}