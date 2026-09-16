rule TTP_XOR_WriteProcessMemory_ffe8 {
  strings:
    $key_ffe8 = { a8 9a [2] 9a b8 [2] 9c 8d [2] b2 8d [2] 8d 91 }

  condition:
    any of them
}