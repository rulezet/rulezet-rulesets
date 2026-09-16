rule TTP_XOR_WriteProcessMemory_dc52 {
  strings:
    $key_dc52 = { 8b 20 [2] b9 02 [2] bf 37 [2] 91 37 [2] ae 2b }

  condition:
    any of them
}