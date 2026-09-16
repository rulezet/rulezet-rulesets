rule TTP_XOR_WriteProcessMemory_fea6 {
  strings:
    $key_fea6 = { a9 d4 [2] 9b f6 [2] 9d c3 [2] b3 c3 [2] 8c df }

  condition:
    any of them
}