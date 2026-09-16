rule TTP_XOR_WriteProcessMemory_62f8 {
  strings:
    $key_62f8 = { 35 8a [2] 07 a8 [2] 01 9d [2] 2f 9d [2] 10 81 }

  condition:
    any of them
}