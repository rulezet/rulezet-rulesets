rule TTP_XOR_WriteProcessMemory_77ce {
  strings:
    $key_77ce = { 20 bc [2] 12 9e [2] 14 ab [2] 3a ab [2] 05 b7 }

  condition:
    any of them
}