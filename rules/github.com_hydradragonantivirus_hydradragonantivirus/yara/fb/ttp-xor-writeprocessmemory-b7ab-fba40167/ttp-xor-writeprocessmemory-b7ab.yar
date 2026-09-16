rule TTP_XOR_WriteProcessMemory_b7ab {
  strings:
    $key_b7ab = { e0 d9 [2] d2 fb [2] d4 ce [2] fa ce [2] c5 d2 }

  condition:
    any of them
}