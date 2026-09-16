rule TTP_XOR_WriteProcessMemory_0efb {
  strings:
    $key_0efb = { 59 89 [2] 6b ab [2] 6d 9e [2] 43 9e [2] 7c 82 }

  condition:
    any of them
}