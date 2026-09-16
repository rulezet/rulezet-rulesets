rule TTP_XOR_WriteProcessMemory_ff31 {
  strings:
    $key_ff31 = { a8 43 [2] 9a 61 [2] 9c 54 [2] b2 54 [2] 8d 48 }

  condition:
    any of them
}