rule TTP_XOR_WriteProcessMemory_f719 {
  strings:
    $key_f719 = { a0 6b [2] 92 49 [2] 94 7c [2] ba 7c [2] 85 60 }

  condition:
    any of them
}