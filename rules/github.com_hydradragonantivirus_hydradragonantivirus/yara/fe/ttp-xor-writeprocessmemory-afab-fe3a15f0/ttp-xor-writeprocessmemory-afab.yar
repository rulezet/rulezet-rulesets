rule TTP_XOR_WriteProcessMemory_afab {
  strings:
    $key_afab = { f8 d9 [2] ca fb [2] cc ce [2] e2 ce [2] dd d2 }

  condition:
    any of them
}