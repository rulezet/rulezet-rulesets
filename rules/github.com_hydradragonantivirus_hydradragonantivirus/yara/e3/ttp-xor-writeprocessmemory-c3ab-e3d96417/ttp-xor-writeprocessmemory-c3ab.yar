rule TTP_XOR_WriteProcessMemory_c3ab {
  strings:
    $key_c3ab = { 94 d9 [2] a6 fb [2] a0 ce [2] 8e ce [2] b1 d2 }

  condition:
    any of them
}