rule TTP_XOR_WriteProcessMemory_e619 {
  strings:
    $key_e619 = { b1 6b [2] 83 49 [2] 85 7c [2] ab 7c [2] 94 60 }

  condition:
    any of them
}