rule TTP_XOR_WriteProcessMemory_44ce {
  strings:
    $key_44ce = { 13 bc [2] 21 9e [2] 27 ab [2] 09 ab [2] 36 b7 }

  condition:
    any of them
}