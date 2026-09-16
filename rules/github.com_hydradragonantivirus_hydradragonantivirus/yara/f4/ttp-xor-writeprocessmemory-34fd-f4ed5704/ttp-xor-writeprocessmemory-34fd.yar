rule TTP_XOR_WriteProcessMemory_34fd {
  strings:
    $key_34fd = { 63 8f [2] 51 ad [2] 57 98 [2] 79 98 [2] 46 84 }

  condition:
    any of them
}