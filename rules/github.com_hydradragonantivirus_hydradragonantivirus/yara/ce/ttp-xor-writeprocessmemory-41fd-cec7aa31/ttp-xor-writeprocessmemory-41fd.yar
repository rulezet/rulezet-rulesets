rule TTP_XOR_WriteProcessMemory_41fd {
  strings:
    $key_41fd = { 16 8f [2] 24 ad [2] 22 98 [2] 0c 98 [2] 33 84 }

  condition:
    any of them
}