rule TTP_XOR_WriteProcessMemory_ff39 {
  strings:
    $key_ff39 = { a8 4b [2] 9a 69 [2] 9c 5c [2] b2 5c [2] 8d 40 }

  condition:
    any of them
}