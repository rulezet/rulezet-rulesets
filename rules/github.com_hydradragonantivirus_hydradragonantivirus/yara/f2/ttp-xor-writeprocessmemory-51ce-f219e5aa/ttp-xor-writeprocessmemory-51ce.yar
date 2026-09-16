rule TTP_XOR_WriteProcessMemory_51ce {
  strings:
    $key_51ce = { 06 bc [2] 34 9e [2] 32 ab [2] 1c ab [2] 23 b7 }

  condition:
    any of them
}