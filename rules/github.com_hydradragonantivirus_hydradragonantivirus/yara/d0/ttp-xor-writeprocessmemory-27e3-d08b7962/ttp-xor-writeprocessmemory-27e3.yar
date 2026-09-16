rule TTP_XOR_WriteProcessMemory_27e3 {
  strings:
    $key_27e3 = { 70 91 [2] 42 b3 [2] 44 86 [2] 6a 86 [2] 55 9a }

  condition:
    any of them
}