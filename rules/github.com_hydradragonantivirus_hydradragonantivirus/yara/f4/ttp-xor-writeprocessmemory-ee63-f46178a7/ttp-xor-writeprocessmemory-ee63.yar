rule TTP_XOR_WriteProcessMemory_ee63 {
  strings:
    $key_ee63 = { b9 11 [2] 8b 33 [2] 8d 06 [2] a3 06 [2] 9c 1a }

  condition:
    any of them
}