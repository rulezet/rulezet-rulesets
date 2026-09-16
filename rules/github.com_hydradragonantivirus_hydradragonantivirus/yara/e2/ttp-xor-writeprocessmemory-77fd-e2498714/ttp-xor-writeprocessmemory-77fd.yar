rule TTP_XOR_WriteProcessMemory_77fd {
  strings:
    $key_77fd = { 20 8f [2] 12 ad [2] 14 98 [2] 3a 98 [2] 05 84 }

  condition:
    any of them
}