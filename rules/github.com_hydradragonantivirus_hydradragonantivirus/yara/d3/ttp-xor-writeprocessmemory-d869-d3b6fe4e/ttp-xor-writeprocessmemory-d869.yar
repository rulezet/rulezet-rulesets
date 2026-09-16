rule TTP_XOR_WriteProcessMemory_d869 {
  strings:
    $key_d869 = { 8f 1b [2] bd 39 [2] bb 0c [2] 95 0c [2] aa 10 }

  condition:
    any of them
}