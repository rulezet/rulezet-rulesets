rule TTP_XOR_WriteProcessMemory_e0fd {
  strings:
    $key_e0fd = { b7 8f [2] 85 ad [2] 83 98 [2] ad 98 [2] 92 84 }

  condition:
    any of them
}