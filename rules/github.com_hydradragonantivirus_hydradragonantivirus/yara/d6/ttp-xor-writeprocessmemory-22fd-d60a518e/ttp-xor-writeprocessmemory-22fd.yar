rule TTP_XOR_WriteProcessMemory_22fd {
  strings:
    $key_22fd = { 75 8f [2] 47 ad [2] 41 98 [2] 6f 98 [2] 50 84 }

  condition:
    any of them
}