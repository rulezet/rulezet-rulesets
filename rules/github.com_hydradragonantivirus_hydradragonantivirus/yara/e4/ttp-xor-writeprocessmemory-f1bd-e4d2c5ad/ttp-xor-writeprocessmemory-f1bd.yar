rule TTP_XOR_WriteProcessMemory_f1bd {
  strings:
    $key_f1bd = { a6 cf [2] 94 ed [2] 92 d8 [2] bc d8 [2] 83 c4 }

  condition:
    any of them
}