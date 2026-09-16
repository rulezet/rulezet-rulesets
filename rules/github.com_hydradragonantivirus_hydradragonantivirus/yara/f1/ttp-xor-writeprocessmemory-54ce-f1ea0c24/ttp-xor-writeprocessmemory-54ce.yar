rule TTP_XOR_WriteProcessMemory_54ce {
  strings:
    $key_54ce = { 03 bc [2] 31 9e [2] 37 ab [2] 19 ab [2] 26 b7 }

  condition:
    any of them
}