rule TTP_XOR_WriteProcessMemory_43f8 {
  strings:
    $key_43f8 = { 14 8a [2] 26 a8 [2] 20 9d [2] 0e 9d [2] 31 81 }

  condition:
    any of them
}