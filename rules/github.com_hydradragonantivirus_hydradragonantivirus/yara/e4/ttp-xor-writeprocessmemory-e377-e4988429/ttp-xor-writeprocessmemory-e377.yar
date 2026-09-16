rule TTP_XOR_WriteProcessMemory_e377 {
  strings:
    $key_e377 = { b4 05 [2] 86 27 [2] 80 12 [2] ae 12 [2] 91 0e }

  condition:
    any of them
}