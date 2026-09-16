rule TTP_XOR_WriteProcessMemory_67ce {
  strings:
    $key_67ce = { 30 bc [2] 02 9e [2] 04 ab [2] 2a ab [2] 15 b7 }

  condition:
    any of them
}