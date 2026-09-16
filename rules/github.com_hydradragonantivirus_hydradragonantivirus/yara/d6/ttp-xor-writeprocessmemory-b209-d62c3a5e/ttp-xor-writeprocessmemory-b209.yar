rule TTP_XOR_WriteProcessMemory_b209 {
  strings:
    $key_b209 = { e5 7b [2] d7 59 [2] d1 6c [2] ff 6c [2] c0 70 }

  condition:
    any of them
}