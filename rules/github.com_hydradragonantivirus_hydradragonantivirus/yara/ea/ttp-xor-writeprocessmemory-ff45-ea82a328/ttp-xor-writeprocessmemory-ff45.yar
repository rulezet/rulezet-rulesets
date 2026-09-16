rule TTP_XOR_WriteProcessMemory_ff45 {
  strings:
    $key_ff45 = { a8 37 [2] 9a 15 [2] 9c 20 [2] b2 20 [2] 8d 3c }

  condition:
    any of them
}