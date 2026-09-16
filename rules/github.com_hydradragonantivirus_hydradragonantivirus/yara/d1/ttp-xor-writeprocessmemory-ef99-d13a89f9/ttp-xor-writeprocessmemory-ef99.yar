rule TTP_XOR_WriteProcessMemory_ef99 {
  strings:
    $key_ef99 = { b8 eb [2] 8a c9 [2] 8c fc [2] a2 fc [2] 9d e0 }

  condition:
    any of them
}