rule TTP_XOR_WriteProcessMemory_6b28 {
  strings:
    $key_6b28 = { 3c 5a [2] 0e 78 [2] 08 4d [2] 26 4d [2] 19 51 }

  condition:
    any of them
}