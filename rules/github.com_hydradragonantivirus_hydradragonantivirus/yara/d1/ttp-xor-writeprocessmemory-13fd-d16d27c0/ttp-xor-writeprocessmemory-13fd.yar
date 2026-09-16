rule TTP_XOR_WriteProcessMemory_13fd {
  strings:
    $key_13fd = { 44 8f [2] 76 ad [2] 70 98 [2] 5e 98 [2] 61 84 }

  condition:
    any of them
}