rule TTP_XOR_WriteProcessMemory_2ee8 {
  strings:
    $key_2ee8 = { 79 9a [2] 4b b8 [2] 4d 8d [2] 63 8d [2] 5c 91 }

  condition:
    any of them
}