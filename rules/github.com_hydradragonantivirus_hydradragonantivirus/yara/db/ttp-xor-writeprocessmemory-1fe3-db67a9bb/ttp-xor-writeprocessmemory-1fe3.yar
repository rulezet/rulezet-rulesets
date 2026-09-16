rule TTP_XOR_WriteProcessMemory_1fe3 {
  strings:
    $key_1fe3 = { 48 91 [2] 7a b3 [2] 7c 86 [2] 52 86 [2] 6d 9a }

  condition:
    any of them
}