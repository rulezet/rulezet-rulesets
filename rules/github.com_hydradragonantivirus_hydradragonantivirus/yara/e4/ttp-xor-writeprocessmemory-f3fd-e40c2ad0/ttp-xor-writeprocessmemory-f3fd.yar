rule TTP_XOR_WriteProcessMemory_f3fd {
  strings:
    $key_f3fd = { a4 8f [2] 96 ad [2] 90 98 [2] be 98 [2] 81 84 }

  condition:
    any of them
}