rule TTP_XOR_WriteProcessMemory_eef8 {
  strings:
    $key_eef8 = { b9 8a [2] 8b a8 [2] 8d 9d [2] a3 9d [2] 9c 81 }

  condition:
    any of them
}