rule TTP_XOR_WriteProcessMemory_c6ab {
  strings:
    $key_c6ab = { 91 d9 [2] a3 fb [2] a5 ce [2] 8b ce [2] b4 d2 }

  condition:
    any of them
}