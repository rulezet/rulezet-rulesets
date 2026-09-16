rule TTP_XOR_WriteProcessMemory_ef55 {
  strings:
    $key_ef55 = { b8 27 [2] 8a 05 [2] 8c 30 [2] a2 30 [2] 9d 2c }

  condition:
    any of them
}