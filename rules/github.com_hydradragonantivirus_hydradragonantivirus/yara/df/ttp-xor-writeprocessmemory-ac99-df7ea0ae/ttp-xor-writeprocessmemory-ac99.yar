rule TTP_XOR_WriteProcessMemory_ac99 {
  strings:
    $key_ac99 = { fb eb [2] c9 c9 [2] cf fc [2] e1 fc [2] de e0 }

  condition:
    any of them
}