rule TTP_XOR_WriteProcessMemory_b231 {
  strings:
    $key_b231 = { e5 43 [2] d7 61 [2] d1 54 [2] ff 54 [2] c0 48 }

  condition:
    any of them
}