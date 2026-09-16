rule TTP_XOR_WriteProcessMemory_5ce3 {
  strings:
    $key_5ce3 = { 0b 91 [2] 39 b3 [2] 3f 86 [2] 11 86 [2] 2e 9a }

  condition:
    any of them
}