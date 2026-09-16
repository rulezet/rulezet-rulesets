rule TTP_XOR_WriteProcessMemory_64fd {
  strings:
    $key_64fd = { 33 8f [2] 01 ad [2] 07 98 [2] 29 98 [2] 16 84 }

  condition:
    any of them
}