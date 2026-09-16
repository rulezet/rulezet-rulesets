rule TTP_XOR_WriteProcessMemory_2b48 {
  strings:
    $key_2b48 = { 7c 3a [2] 4e 18 [2] 48 2d [2] 66 2d [2] 59 31 }

  condition:
    any of them
}