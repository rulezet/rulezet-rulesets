rule TTP_XOR_WriteProcessMemory_6128 {
  strings:
    $key_6128 = { 36 5a [2] 04 78 [2] 02 4d [2] 2c 4d [2] 13 51 }

  condition:
    any of them
}