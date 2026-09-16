rule TTP_XOR_WriteProcessMemory_e759 {
  strings:
    $key_e759 = { b0 2b [2] 82 09 [2] 84 3c [2] aa 3c [2] 95 20 }

  condition:
    any of them
}