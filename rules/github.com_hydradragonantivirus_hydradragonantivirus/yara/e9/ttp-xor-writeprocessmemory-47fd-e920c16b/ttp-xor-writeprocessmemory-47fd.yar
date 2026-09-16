rule TTP_XOR_WriteProcessMemory_47fd {
  strings:
    $key_47fd = { 10 8f [2] 22 ad [2] 24 98 [2] 0a 98 [2] 35 84 }

  condition:
    any of them
}