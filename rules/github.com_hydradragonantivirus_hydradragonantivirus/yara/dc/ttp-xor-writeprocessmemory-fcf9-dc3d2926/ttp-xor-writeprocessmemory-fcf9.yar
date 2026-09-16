rule TTP_XOR_WriteProcessMemory_fcf9 {
  strings:
    $key_fcf9 = { ab 8b [2] 99 a9 [2] 9f 9c [2] b1 9c [2] 8e 80 }

  condition:
    any of them
}