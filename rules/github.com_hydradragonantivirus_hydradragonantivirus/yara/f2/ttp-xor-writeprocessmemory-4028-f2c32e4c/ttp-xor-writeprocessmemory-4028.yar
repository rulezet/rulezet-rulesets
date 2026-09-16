rule TTP_XOR_WriteProcessMemory_4028 {
  strings:
    $key_4028 = { 17 5a [2] 25 78 [2] 23 4d [2] 0d 4d [2] 32 51 }

  condition:
    any of them
}