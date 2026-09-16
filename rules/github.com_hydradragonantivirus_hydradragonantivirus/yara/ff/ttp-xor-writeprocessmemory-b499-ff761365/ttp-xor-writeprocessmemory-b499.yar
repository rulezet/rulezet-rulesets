rule TTP_XOR_WriteProcessMemory_b499 {
  strings:
    $key_b499 = { e3 eb [2] d1 c9 [2] d7 fc [2] f9 fc [2] c6 e0 }

  condition:
    any of them
}