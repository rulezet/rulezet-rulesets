rule TTP_XOR_WriteProcessMemory_6e61 {
  strings:
    $key_6e61 = { 39 13 [2] 0b 31 [2] 0d 04 [2] 23 04 [2] 1c 18 }

  condition:
    any of them
}