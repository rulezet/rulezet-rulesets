rule TTP_XOR_WriteProcessMemory_6efb {
  strings:
    $key_6efb = { 39 89 [2] 0b ab [2] 0d 9e [2] 23 9e [2] 1c 82 }

  condition:
    any of them
}