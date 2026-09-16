rule TTP_XOR_WriteProcessMemory_90f4 {
  strings:
    $key_90f4 = { c7 86 [2] f5 a4 [2] f3 91 [2] dd 91 [2] e2 8d }

  condition:
    any of them
}