rule TTP_XOR_WriteProcessMemory_e4fd {
  strings:
    $key_e4fd = { b3 8f [2] 81 ad [2] 87 98 [2] a9 98 [2] 96 84 }

  condition:
    any of them
}