rule TTP_XOR_WriteProcessMemory_cdc6 {
  strings:
    $key_cdc6 = { 9a b4 [2] a8 96 [2] ae a3 [2] 80 a3 [2] bf bf }

  condition:
    any of them
}