rule TTP_XOR_WriteProcessMemory_dc67 {
  strings:
    $key_dc67 = { 8b 15 [2] b9 37 [2] bf 02 [2] 91 02 [2] ae 1e }

  condition:
    any of them
}