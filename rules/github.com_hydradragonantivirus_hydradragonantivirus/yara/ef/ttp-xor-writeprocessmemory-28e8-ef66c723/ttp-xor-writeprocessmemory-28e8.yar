rule TTP_XOR_WriteProcessMemory_28e8 {
  strings:
    $key_28e8 = { 7f 9a [2] 4d b8 [2] 4b 8d [2] 65 8d [2] 5a 91 }

  condition:
    any of them
}