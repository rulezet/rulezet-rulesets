rule TTP_XOR_WriteProcessMemory_aa99 {
  strings:
    $key_aa99 = { fd eb [2] cf c9 [2] c9 fc [2] e7 fc [2] d8 e0 }

  condition:
    any of them
}