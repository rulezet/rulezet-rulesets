rule TTP_XOR_WriteProcessMemory_60ee {
  strings:
    $key_60ee = { 37 9c [2] 05 be [2] 03 8b [2] 2d 8b [2] 12 97 }

  condition:
    any of them
}