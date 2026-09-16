rule TTP_XOR_WriteProcessMemory_eaa7 {
  strings:
    $key_eaa7 = { bd d5 [2] 8f f7 [2] 89 c2 [2] a7 c2 [2] 98 de }

  condition:
    any of them
}