rule TTP_XOR_WriteProcessMemory_32fd {
  strings:
    $key_32fd = { 65 8f [2] 57 ad [2] 51 98 [2] 7f 98 [2] 40 84 }

  condition:
    any of them
}