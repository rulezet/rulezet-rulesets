rule TTP_XOR_WriteProcessMemory_63fd {
  strings:
    $key_63fd = { 34 8f [2] 06 ad [2] 00 98 [2] 2e 98 [2] 11 84 }

  condition:
    any of them
}