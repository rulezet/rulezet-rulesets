rule TTP_XOR_WriteProcessMemory_e7fd {
  strings:
    $key_e7fd = { b0 8f [2] 82 ad [2] 84 98 [2] aa 98 [2] 95 84 }

  condition:
    any of them
}