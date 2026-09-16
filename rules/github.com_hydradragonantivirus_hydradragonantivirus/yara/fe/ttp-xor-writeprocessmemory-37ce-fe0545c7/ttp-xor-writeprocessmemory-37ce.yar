rule TTP_XOR_WriteProcessMemory_37ce {
  strings:
    $key_37ce = { 60 bc [2] 52 9e [2] 54 ab [2] 7a ab [2] 45 b7 }

  condition:
    any of them
}