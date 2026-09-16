rule TTP_XOR_WriteProcessMemory_e321 {
  strings:
    $key_e321 = { b4 53 [2] 86 71 [2] 80 44 [2] ae 44 [2] 91 58 }

  condition:
    any of them
}