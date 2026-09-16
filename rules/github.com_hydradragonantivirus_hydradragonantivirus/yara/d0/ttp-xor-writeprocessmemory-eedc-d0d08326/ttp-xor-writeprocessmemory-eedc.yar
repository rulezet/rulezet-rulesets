rule TTP_XOR_WriteProcessMemory_eedc {
  strings:
    $key_eedc = { b9 ae [2] 8b 8c [2] 8d b9 [2] a3 b9 [2] 9c a5 }

  condition:
    any of them
}