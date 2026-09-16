rule TTP_XOR_WriteProcessMemory_ff34 {
  strings:
    $key_ff34 = { a8 46 [2] 9a 64 [2] 9c 51 [2] b2 51 [2] 8d 4d }

  condition:
    any of them
}