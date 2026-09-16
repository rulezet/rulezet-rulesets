rule TTP_XOR_WriteProcessMemory_3efb {
  strings:
    $key_3efb = { 69 89 [2] 5b ab [2] 5d 9e [2] 73 9e [2] 4c 82 }

  condition:
    any of them
}