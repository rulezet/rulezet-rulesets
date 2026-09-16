rule TTP_XOR_WriteProcessMemory_ffe3 {
  strings:
    $key_ffe3 = { a8 91 [2] 9a b3 [2] 9c 86 [2] b2 86 [2] 8d 9a }

  condition:
    any of them
}