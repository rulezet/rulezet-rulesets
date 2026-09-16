rule TTP_XOR_WriteProcessMemory_34ce {
  strings:
    $key_34ce = { 63 bc [2] 51 9e [2] 57 ab [2] 79 ab [2] 46 b7 }

  condition:
    any of them
}