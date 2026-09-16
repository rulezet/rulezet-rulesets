rule TTP_XOR_WriteProcessMemory_7a40 {
  strings:
    $key_7a40 = { 2d 32 [2] 1f 10 [2] 19 25 [2] 37 25 [2] 08 39 }

  condition:
    any of them
}