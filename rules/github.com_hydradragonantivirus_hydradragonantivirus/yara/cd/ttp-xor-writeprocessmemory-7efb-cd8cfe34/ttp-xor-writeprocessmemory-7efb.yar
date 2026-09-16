rule TTP_XOR_WriteProcessMemory_7efb {
  strings:
    $key_7efb = { 29 89 [2] 1b ab [2] 1d 9e [2] 33 9e [2] 0c 82 }

  condition:
    any of them
}