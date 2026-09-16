rule TTP_XOR_WriteProcessMemory_67fd {
  strings:
    $key_67fd = { 30 8f [2] 02 ad [2] 04 98 [2] 2a 98 [2] 15 84 }

  condition:
    any of them
}