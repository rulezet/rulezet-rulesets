rule TTP_XOR_WriteProcessMemory_346e {
  strings:
    $key_346e = { 63 1c [2] 51 3e [2] 57 0b [2] 79 0b [2] 46 17 }

  condition:
    any of them
}