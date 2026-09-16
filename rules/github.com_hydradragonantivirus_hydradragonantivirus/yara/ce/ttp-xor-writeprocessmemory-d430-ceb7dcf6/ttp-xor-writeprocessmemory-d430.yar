rule TTP_XOR_WriteProcessMemory_d430 {
  strings:
    $key_d430 = { 83 42 [2] b1 60 [2] b7 55 [2] 99 55 [2] a6 49 }

  condition:
    any of them
}