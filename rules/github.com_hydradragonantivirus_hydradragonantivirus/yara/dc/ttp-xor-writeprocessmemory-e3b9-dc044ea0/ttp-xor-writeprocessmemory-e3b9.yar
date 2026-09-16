rule TTP_XOR_WriteProcessMemory_e3b9 {
  strings:
    $key_e3b9 = { b4 cb [2] 86 e9 [2] 80 dc [2] ae dc [2] 91 c0 }

  condition:
    any of them
}