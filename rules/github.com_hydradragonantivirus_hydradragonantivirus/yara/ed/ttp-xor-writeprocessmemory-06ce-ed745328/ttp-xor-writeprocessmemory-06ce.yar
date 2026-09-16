rule TTP_XOR_WriteProcessMemory_06ce {
  strings:
    $key_06ce = { 51 bc [2] 63 9e [2] 65 ab [2] 4b ab [2] 74 b7 }

  condition:
    any of them
}