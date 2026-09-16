rule TTP_XOR_WriteProcessMemory_27e8 {
  strings:
    $key_27e8 = { 70 9a [2] 42 b8 [2] 44 8d [2] 6a 8d [2] 55 91 }

  condition:
    any of them
}