rule TTP_XOR_WriteProcessMemory_5a20 {
  strings:
    $key_5a20 = { 0d 52 [2] 3f 70 [2] 39 45 [2] 17 45 [2] 28 59 }

  condition:
    any of them
}