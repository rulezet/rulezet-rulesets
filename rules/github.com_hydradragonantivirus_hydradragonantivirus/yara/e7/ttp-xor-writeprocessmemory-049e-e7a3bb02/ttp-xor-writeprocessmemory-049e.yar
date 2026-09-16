rule TTP_XOR_WriteProcessMemory_049e {
  strings:
    $key_049e = { 53 ec [2] 61 ce [2] 67 fb [2] 49 fb [2] 76 e7 }

  condition:
    any of them
}