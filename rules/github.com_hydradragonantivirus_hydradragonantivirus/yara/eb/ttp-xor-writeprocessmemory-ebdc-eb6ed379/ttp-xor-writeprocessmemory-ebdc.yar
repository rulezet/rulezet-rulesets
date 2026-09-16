rule TTP_XOR_WriteProcessMemory_ebdc {
  strings:
    $key_ebdc = { bc ae [2] 8e 8c [2] 88 b9 [2] a6 b9 [2] 99 a5 }

  condition:
    any of them
}