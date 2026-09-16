rule TTP_XOR_WriteProcessMemory_bee4 {
  strings:
    $key_bee4 = { e9 96 [2] db b4 [2] dd 81 [2] f3 81 [2] cc 9d }

  condition:
    any of them
}