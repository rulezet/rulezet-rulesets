rule TTP_XOR_WriteProcessMemory_f519 {
  strings:
    $key_f519 = { a2 6b [2] 90 49 [2] 96 7c [2] b8 7c [2] 87 60 }

  condition:
    any of them
}