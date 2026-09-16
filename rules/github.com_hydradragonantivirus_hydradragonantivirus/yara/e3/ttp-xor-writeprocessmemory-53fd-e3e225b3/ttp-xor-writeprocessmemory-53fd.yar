rule TTP_XOR_WriteProcessMemory_53fd {
  strings:
    $key_53fd = { 04 8f [2] 36 ad [2] 30 98 [2] 1e 98 [2] 21 84 }

  condition:
    any of them
}