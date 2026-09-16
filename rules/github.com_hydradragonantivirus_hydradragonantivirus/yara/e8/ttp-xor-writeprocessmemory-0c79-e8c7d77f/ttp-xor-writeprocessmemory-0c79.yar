rule TTP_XOR_WriteProcessMemory_0c79 {
  strings:
    $key_0c79 = { 5b 0b [2] 69 29 [2] 6f 1c [2] 41 1c [2] 7e 00 }

  condition:
    any of them
}