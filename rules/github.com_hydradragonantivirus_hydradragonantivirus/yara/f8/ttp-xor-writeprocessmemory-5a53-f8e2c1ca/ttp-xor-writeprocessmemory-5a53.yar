rule TTP_XOR_WriteProcessMemory_5a53 {
  strings:
    $key_5a53 = { 0d 21 [2] 3f 03 [2] 39 36 [2] 17 36 [2] 28 2a }

  condition:
    any of them
}