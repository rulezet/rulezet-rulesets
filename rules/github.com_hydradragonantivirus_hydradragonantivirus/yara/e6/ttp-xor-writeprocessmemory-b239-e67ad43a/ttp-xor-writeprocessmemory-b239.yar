rule TTP_XOR_WriteProcessMemory_b239 {
  strings:
    $key_b239 = { e5 4b [2] d7 69 [2] d1 5c [2] ff 5c [2] c0 40 }

  condition:
    any of them
}