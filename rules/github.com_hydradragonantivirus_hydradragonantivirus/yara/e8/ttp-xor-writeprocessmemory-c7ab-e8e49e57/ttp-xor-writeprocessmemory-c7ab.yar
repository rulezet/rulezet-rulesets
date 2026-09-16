rule TTP_XOR_WriteProcessMemory_c7ab {
  strings:
    $key_c7ab = { 90 d9 [2] a2 fb [2] a4 ce [2] 8a ce [2] b5 d2 }

  condition:
    any of them
}